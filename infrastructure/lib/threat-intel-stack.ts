import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as bedrock from "aws-cdk-lib/aws-bedrock";
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

function loadPrompt(filename: string): string {
  const promptPath = path.join(__dirname, "../../prompts", filename);
  return fs.readFileSync(promptPath, "utf-8");
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

export class ThreatIntelStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const config = loadConfig();
    const lambdaCode = createLambdaCode();

    // --- Storage ---

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

    threatsTable.addGlobalSecondaryIndex({
      indexName: "stix-id-index",
      partitionKey: { name: "stix_id", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // --- Queues ---

    const ingestionQueue = new sqs.Queue(this, "IngestionQueue", {
      visibilityTimeout: cdk.Duration.minutes(5),
    });

    // --- Notifications ---

    const notificationTopic = new sns.Topic(this, "ThreatNotifications", {
      displayName: "TasNetworks Threat Intel Notifications",
    });

    const uniqueEmails = [...new Set(config.asset_categories.map((c) => c.notify_email))];
    for (const email of uniqueEmails) {
      notificationTopic.addSubscription(new snsSubscriptions.EmailSubscription(email));
    }

    // --- Bedrock Agent IAM Role ---

    const agentRole = new iam.Role(this, "BedrockAgentRole", {
      assumedBy: new iam.ServicePrincipal("bedrock.amazonaws.com"),
      description: "Role assumed by Bedrock Agents for the threat intel pipeline",
    });

    const modelId = config.bedrock_model_id;
    const isInferenceProfile = /^(us|eu|global)\./.test(modelId);
    const modelResources: string[] = isInferenceProfile
      ? [
          `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${modelId}`,
          `arn:aws:bedrock:*::foundation-model/${modelId.replace(/^(us|eu|global)\./, "")}`,
        ]
      : [`arn:aws:bedrock:${this.region}::foundation-model/${modelId}`];

    agentRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel"],
        resources: modelResources,
      })
    );

    // --- Bedrock Agents ---

    const classifierInstruction = loadPrompt("classifier_agent.md");

    const classifierAgent = new bedrock.CfnAgent(this, "ClassifierAgent", {
      agentName: "ThreatIntelClassifier",
      description: "Classifies STIX 2.1 threat intelligence into asset categories",
      foundationModel: config.bedrock_model_id,
      instruction: classifierInstruction,
      agentResourceRoleArn: agentRole.roleArn,
      idleSessionTtlInSeconds: 600,
      autoPrepare: true,
    });

    const classifierAlias = new bedrock.CfnAgentAlias(this, "ClassifierAgentAlias", {
      agentId: classifierAgent.attrAgentId,
      agentAliasName: "live",
    });

    const specialistAgents: Record<string, { agent: bedrock.CfnAgent; alias: bedrock.CfnAgentAlias }> = {};

    for (const category of config.asset_categories) {
      const instruction = loadPrompt(`specialist_${category.id}.md`);

      const agent = new bedrock.CfnAgent(this, `SpecialistAgent-${category.id}`, {
        agentName: `ThreatIntelSpecialist-${category.id}`,
        description: `Specialist analyst for ${category.display_name} threats`,
        foundationModel: config.bedrock_model_id,
        instruction: instruction,
        agentResourceRoleArn: agentRole.roleArn,
        idleSessionTtlInSeconds: 600,
        autoPrepare: true,
      });

      const alias = new bedrock.CfnAgentAlias(this, `SpecialistAgentAlias-${category.id}`, {
        agentId: agent.attrAgentId,
        agentAliasName: "live",
      });

      specialistAgents[category.id] = { agent, alias };
    }

    // --- Lambda Functions ---

    const createLambdaLogGroup = (logId: string) =>
      new logs.LogGroup(this, `${logId}LogGroup`, {
        retention: logs.RetentionDays.ONE_WEEK,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

    const lambdaDefaults: Partial<lambda.FunctionProps> = {
      runtime: lambda.Runtime.PYTHON_3_12,
      code: lambdaCode,
      timeout: cdk.Duration.minutes(3),
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

    // Build specialist agent alias ARN map for the orchestrator
    const specialistAliasArns: Record<string, string> = {};
    for (const category of config.asset_categories) {
      const { alias } = specialistAgents[category.id];
      specialistAliasArns[category.id] = `arn:aws:bedrock:${this.region}:${this.account}:agent-alias/${specialistAgents[category.id].agent.attrAgentId}/${alias.attrAgentAliasId}`;
    }

    const orchestratorFn = new lambda.Function(this, "OrchestratorFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("OrchestratorFn"),
      handler: "orchestrator.handler.handler",
      timeout: cdk.Duration.minutes(5),
      environment: {
        TABLE_NAME: threatsTable.tableName,
        NOTIFICATION_TOPIC_ARN: notificationTopic.topicArn,
        CLASSIFIER_AGENT_ID: classifierAgent.attrAgentId,
        CLASSIFIER_AGENT_ALIAS_ID: classifierAlias.attrAgentAliasId,
        SPECIALIST_AGENT_IDS: JSON.stringify(
          Object.fromEntries(
            config.asset_categories.map((c) => [
              c.id,
              specialistAgents[c.id].agent.attrAgentId,
            ])
          )
        ),
        SPECIALIST_AGENT_ALIAS_IDS: JSON.stringify(
          Object.fromEntries(
            config.asset_categories.map((c) => [
              c.id,
              specialistAgents[c.id].alias.attrAgentAliasId,
            ])
          )
        ),
        ASSET_CATEGORIES_JSON: JSON.stringify(config),
        WEBHOOK_URL: process.env.WEBHOOK_URL ?? "https://th-0fbaf552e7a542398039f841c2dec7d4.ecs.us-east-1.on.aws",
      },
    } as lambda.FunctionProps);

    orchestratorFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeAgent"],
        resources: [
          `arn:aws:bedrock:${this.region}:${this.account}:agent/*`,
          `arn:aws:bedrock:${this.region}:${this.account}:agent-alias/*`,
        ],
      })
    );

    const markProcessedFn = new lambda.Function(this, "MarkProcessedFn", {
      ...lambdaDefaults,
      logGroup: createLambdaLogGroup("MarkProcessedFn"),
      handler: "mark_processed.handler.handler",
      environment: {
        TABLE_NAME: threatsTable.tableName,
      },
    } as lambda.FunctionProps);

    // --- Permissions ---

    rawBucket.grantReadWrite(ingestFn);
    threatsTable.grantReadWriteData(ingestFn);
    threatsTable.grantReadWriteData(orchestratorFn);
    threatsTable.grantReadWriteData(markProcessedFn);
    ingestionQueue.grantSendMessages(ingestFn);
    ingestionQueue.grantConsumeMessages(orchestratorFn);
    notificationTopic.grantPublish(orchestratorFn);

    // --- Event Sources ---

    orchestratorFn.addEventSource(
      new lambdaEventSources.SqsEventSource(ingestionQueue, { batchSize: 1 })
    );

    // --- API Gateway ---

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

    // --- Outputs ---

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

    new cdk.CfnOutput(this, "ClassifierAgentId", {
      value: classifierAgent.attrAgentId,
      description: "Bedrock Agent ID for the classifier",
    });

    for (const category of config.asset_categories) {
      new cdk.CfnOutput(this, `SpecialistAgentId-${category.id}`, {
        value: specialistAgents[category.id].agent.attrAgentId,
        description: `Bedrock Agent ID for ${category.display_name} specialist`,
      });
    }
  }
}
