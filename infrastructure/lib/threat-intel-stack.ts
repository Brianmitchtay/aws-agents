import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sns from "aws-cdk-lib/aws-sns";
import * as snsSubscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";

interface AssetCategory {
  id: string;
  display_name: string;
  description: string;
  notify_email: string;
}

interface PipelineConfig {
  bedrock_model_id: string;
  severity_levels: string[];
  asset_categories: AssetCategory[];
}

function loadConfig(): PipelineConfig {
  const configPath = path.join(__dirname, "../../config/asset_categories.json");
  return JSON.parse(fs.readFileSync(configPath, "utf-8"));
}

function bundleLambdaAsset(outputDir: string): void {
  const repoRoot = path.join(__dirname, "../..");
  fs.mkdirSync(outputDir, { recursive: true });

  execSync(`cp -R "${path.join(repoRoot, "lambdas")}/." "${outputDir}/"`);
  execSync(`cp -R "${path.join(repoRoot, "prompts")}" "${outputDir}/prompts"`);
}

function createLambdaCode(): lambda.Code {
  const repoRoot = path.join(__dirname, "../..");
  return lambda.Code.fromAsset(repoRoot, {
    bundling: {
      image: lambda.Runtime.PYTHON_3_12.bundlingImage,
      command: [
        "bash",
        "-c",
        [
          "pip install -r lambdas/requirements.txt -t /asset-output",
          "cp -r lambdas/* /asset-output/",
          "cp -r prompts /asset-output/prompts",
        ].join(" && "),
      ],
      local: {
        tryBundle(outputDir: string): boolean {
          try {
            bundleLambdaAsset(outputDir);
            return true;
          } catch {
            return false;
          }
        },
      },
    },
    exclude: [
      "infrastructure/**",
      ".git/**",
      "**/__pycache__/**",
      "**/*.pyc",
    ],
  });
}

function bedrockPolicyResources(region: string, account: string, modelId: string): string[] {
  // Geo/global inference profiles (e.g. au.anthropic.claude-sonnet-4-6) route to
  // foundation models in multiple regions — wildcard the region on foundation-model.
  if (/^(au|us|eu|global)\./.test(modelId)) {
    const foundationModelId = modelId.replace(/^(au|us|eu|global)\./, "");
    return [
      `arn:aws:bedrock:${region}:${account}:inference-profile/${modelId}`,
      `arn:aws:bedrock:*::foundation-model/${foundationModelId}`,
    ];
  }
  return [`arn:aws:bedrock:${region}::foundation-model/${modelId}`];
}

export class ThreatIntelStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const config = loadConfig();
    const configJson = JSON.stringify(config);
    const lambdaCode = createLambdaCode();

    const rawBucket = new s3.Bucket(this, "RawThreatIntel", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const threatsTable = new dynamodb.Table(this, "Threats", {
      partitionKey: { name: "threat_id", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    threatsTable.addGlobalSecondaryIndex({
      indexName: "dedup-index",
      partitionKey: { name: "dedup_hash", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    const ingestionQueue = new sqs.Queue(this, "IngestionQueue", {
      visibilityTimeout: cdk.Duration.minutes(5),
    });

    const specialistQueues: Record<string, sqs.Queue> = {};
    for (const category of config.asset_categories) {
      specialistQueues[category.id] = new sqs.Queue(this, `SpecialistQueue-${category.id}`, {
        visibilityTimeout: cdk.Duration.minutes(5),
      });
    }

    const notificationTopic = new sns.Topic(this, "ThreatNotifications", {
      displayName: "REDACTED Threat Intel Notifications",
    });

    const uniqueEmails = [...new Set(config.asset_categories.map((c) => c.notify_email))];
    for (const email of uniqueEmails) {
      notificationTopic.addSubscription(new snsSubscriptions.EmailSubscription(email));
    }

    const bedrockPolicy = new iam.PolicyStatement({
      actions: ["bedrock:InvokeModel", "bedrock:Converse"],
      resources: bedrockPolicyResources(this.region, this.account, config.bedrock_model_id),
    });

    const createLambdaLogGroup = (id: string) =>
      new logs.LogGroup(this, `${id}LogGroup`, {
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

    const lambdaDefaults: Partial<lambda.FunctionProps> = {
      runtime: lambda.Runtime.PYTHON_3_12,
      code: lambdaCode,
      timeout: cdk.Duration.minutes(2),
      memorySize: 512,
    };

    const ingestFn = new lambda.Function(this, "IngestFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("IngestFn"),
      handler: "ingest.handler.handler",
      environment: {
        RAW_BUCKET: rawBucket.bucketName,
        TABLE_NAME: threatsTable.tableName,
        INGESTION_QUEUE_URL: ingestionQueue.queueUrl,
      },
    } as lambda.FunctionProps);

    const classifierFn = new lambda.Function(this, "ClassifierFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("ClassifierFn"),
      handler: "classifier.handler.handler",
      environment: {
        TABLE_NAME: threatsTable.tableName,
        SPECIALIST_QUEUE_URLS: JSON.stringify(
          Object.fromEntries(
            config.asset_categories.map((c) => [c.id, specialistQueues[c.id].queueUrl])
          )
        ),
        BEDROCK_MODEL_ID: config.bedrock_model_id,
        ASSET_CATEGORIES_JSON: configJson,
        PROMPTS_DIR: "/var/task/prompts",
      },
    } as lambda.FunctionProps);
    classifierFn.addToRolePolicy(bedrockPolicy);

    const specialistFn = new lambda.Function(this, "SpecialistFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("SpecialistFn"),
      handler: "specialist.handler.handler",
      environment: {
        TABLE_NAME: threatsTable.tableName,
        NOTIFICATION_TOPIC_ARN: notificationTopic.topicArn,
        BEDROCK_MODEL_ID: config.bedrock_model_id,
        ASSET_CATEGORIES_JSON: configJson,
        PROMPTS_DIR: "/var/task/prompts",
      },
    } as lambda.FunctionProps);
    specialistFn.addToRolePolicy(bedrockPolicy);

    const markProcessedFn = new lambda.Function(this, "MarkProcessedFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("MarkProcessedFn"),
      handler: "mark_processed.handler.handler",
      environment: {
        TABLE_NAME: threatsTable.tableName,
      },
    } as lambda.FunctionProps);

    rawBucket.grantReadWrite(ingestFn);
    threatsTable.grantReadWriteData(ingestFn);
    threatsTable.grantReadWriteData(classifierFn);
    threatsTable.grantReadWriteData(specialistFn);
    threatsTable.grantReadWriteData(markProcessedFn);
    ingestionQueue.grantSendMessages(ingestFn);
    ingestionQueue.grantConsumeMessages(classifierFn);

    for (const category of config.asset_categories) {
      specialistQueues[category.id].grantSendMessages(classifierFn);
      specialistQueues[category.id].grantConsumeMessages(specialistFn);
    }
    notificationTopic.grantPublish(specialistFn);

    classifierFn.addEventSource(
      new lambdaEventSources.SqsEventSource(ingestionQueue, { batchSize: 1 })
    );

    for (const category of config.asset_categories) {
      specialistFn.addEventSource(
        new lambdaEventSources.SqsEventSource(specialistQueues[category.id], { batchSize: 1 })
      );
    }

    const api = new apigateway.RestApi(this, "ThreatIntelApi", {
      restApiName: "Threat Intel Ingestion API",
      description: "Webhook endpoint for threat intelligence feeds",
      deployOptions: { stageName: "prod" },
    });

    const threats = api.root.addResource("threats");
    threats.addMethod("POST", new apigateway.LambdaIntegration(ingestFn));

    const threatById = threats.addResource("{threat_id}");
    threatById
      .addResource("processed")
      .addMethod("POST", new apigateway.LambdaIntegration(markProcessedFn));

    new cdk.CfnOutput(this, "IngestUrl", {
      value: `${api.url}threats`,
      description: "POST threat intelligence payloads here",
    });

    new cdk.CfnOutput(this, "MarkProcessedUrl", {
      value: `${api.url}threats/{threat_id}/processed`,
      description: "POST to mark a threat as processed (include feedback in body)",
    });

    new cdk.CfnOutput(this, "NotificationTopicArn", {
      value: notificationTopic.topicArn,
      description: "SNS topic for threat digests — confirm email subscriptions after deploy",
    });

    new cdk.CfnOutput(this, "ThreatsTableName", {
      value: threatsTable.tableName,
    });
  }
}
