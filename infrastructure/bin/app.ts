#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { ThreatIntelStack } from "../lib/threat-intel-stack";

const app = new cdk.App();

new ThreatIntelStack(app, "ThreatIntelStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
  },
  description: "TAS Networks threat intelligence multi-agent pipeline (hackathon prototype)",
});
