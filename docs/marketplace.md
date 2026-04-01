# Open Pic - Cloud Marketplace Integration Guide

## Overview

Open Pic (secure-agent-core) は AWS、Azure、Google Cloud の各マーケットプレイスに対応しています。
これにより、既存のクラウドインフラストラクチャとの統合が容易になり、請求も一元化されます。

---

## 🚀 AWS Marketplace

### インストール

1. **AWS Marketplaceから購読**
   ```
   https://aws.amazon.com/marketplace/pp/prodview-openpic-secure-agent
   ```

2. **CloudFormationスタックのデプロイ**
   ```bash
   aws cloudformation create-stack \
     --stack-name openpic-security \
     --template-url https://s3.amazonaws.com/openpic-cfn/template.yaml \
     --parameters \
       ParameterKey=TenantId,ParameterValue=your_company \
       ParameterKey=ApiKey,ParameterValue=your_api_key
   ```

3. **VPC統合**
   ```yaml
   # vpc-integration.yaml
   Resources:
     OpenPicSecurityGroup:
       Type: AWS::EC2::SecurityGroup
       Properties:
         GroupDescription: OpenPic Security Layer
         VpcId: !Ref VpcId
         SecurityGroupIngress:
           - IpProtocol: tcp
             FromPort: 443
             ToPort: 443
             CidrIp: 0.0.0.0/0
   ```

### Bedrock統合

```python
import boto3
from openpic_sdk import SecureLLMClient, Provider

# Bedrockクライアント
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

# OpenPicセキュリティレイヤー
openpic = SecureLLMClient(
    openpic_api_key="sk_openpic_xxx",
    tenant_id="aws_company"
)

async def secure_bedrock_call(prompt: str):
    """Bedrockを安全に呼び出す"""
    
    # 1. 入力スキャン
    input_scan = await openpic.scan_input(prompt)
    if not input_scan.is_safe:
        raise SecurityException("Prompt blocked by security guard")
    
    # 2. Bedrock呼び出し
    response = bedrock.invoke_model(
        modelId='anthropic.claude-3-opus-20240229-v1:0',
        body=json.dumps({
            "prompt": input_scan.cleaned_prompt,
            "max_tokens": 1000
        })
    )
    
    # 3. 出力スキャン
    output_scan = await openpic.scan_output(response['body'].read())
    
    return output_scan.safe_output
```

### 使用量メトリクスのレポート

```python
import boto3

marketplace = boto3.client('meteringmarketplace')

# 使用量を報告
marketplace.meter_usage(
    ProductCode='openpic-prod-code',
    Timestamp=datetime.now(),
    UsageDimension='requests',
    UsageQuantity=1000,  # 1000リクエスト
    DryRun=False
)
```

### 価格プラン

| プラン | 月額 | リクエスト数 | 機能 |
|--------|------|--------------|------|
| Free | $0 | 10,000 | 基本セキュリティ |
| Starter | $499 | 100,000 | 高度なセキュリティ、分析 |
| Business | $1,999 | Unlimited | カスタムポリシー、SLA |
| Enterprise | カスタム | Unlimited | 専用インフラ、CSM |

---

## ☁️ Azure Marketplace

### インストール

1. **Azure Marketplaceから購読**
   ```
   https://azuremarketplace.microsoft.com/en-us/marketplace/apps/openpic-security
   ```

2. **ARM Templateデプロイ**
   ```bash
   az deployment group create \
     --resource-group openpic-rg \
     --template-file azuredeploy.json \
     --parameters \
       tenantId=your_company \
       apiKey=your_api_key
   ```

### Azure OpenAI統合

```python
from azure.identity import DefaultAzureCredential
from azure.ai.openai import OpenAIClient
from openpic_sdk import SecureLLMClient

# Azure OpenAI
credential = DefaultAzureCredential()
openai_client = OpenAIClient(
    endpoint="https://your-resource.openai.azure.com",
    credential=credential
)

# OpenPicセキュリティ
openpic = SecureLLMClient(
    openpic_api_key="sk_openpic_xxx",
    tenant_id="azure_company"
)

async def secure_azure_openai_call(prompt: str):
    """Azure OpenAIを安全に呼び出す"""
    
    # セキュリティチェック付きで呼び出し
    response = await openpic.call(
        provider=Provider.OPENAI,
        model="gpt-4",
        prompt=prompt,
        azure_deployment="your-gpt4-deployment"
    )
    
    return response.content
```

### 使用量レポート

```python
from azure.mgmt.marketplace import MarketplaceOrderingAgreements

# 使用量を報告
marketplace = MarketplaceOrderingAgreements(credential, subscription_id)
marketplace.usage_events.create(
    resource_uri="/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.SaaS/resources/{resource}",
    usage_event={
        "dimension": "requests",
        "quantity": 1000,
        "effectiveStartTime": datetime.now().isoformat()
    }
)
```

### Private Link統合

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {
      "type": "Microsoft.Network/privateEndpoints",
      "apiVersion": "2021-05-01",
      "name": "openpic-private-endpoint",
      "location": "[resourceGroup().location]",
      "properties": {
        "subnet": {
          "id": "[parameters('subnetId')]"
        },
        "privateLinkServiceConnections": [
          {
            "name": "openpic-connection",
            "properties": {
              "privateLinkServiceId": "[parameters('openpicServiceId')]"
            }
          }
        ]
      }
    }
  ]
}
```

---

## 🔷 Google Cloud Marketplace

### インストール

1. **GCP Marketplaceから購読**
   ```
   https://console.cloud.google.com/marketplace/product/openpic-public/secure-agent-core
   ```

2. **Deployment Manager**
   ```bash
   gcloud deployment-manager deployments create openpic-deployment \
     --config openpic.yaml \
     --properties tenantId:your_company,apiKey:your_api_key
   ```

### Vertex AI統合

```python
from google.cloud import aiplatform
from openpic_sdk import SecureLLMClient, Provider

# Vertex AI初期化
aiplatform.init(project='your-project', location='us-central1')

# OpenPicセキュリティ
openpic = SecureLLMClient(
    openpic_api_key="sk_openpic_xxx",
    tenant_id="gcp_company"
)

async def secure_vertex_ai_call(prompt: str):
    """Vertex AIを安全に呼び出す"""
    
    response = await openpic.call(
        provider=Provider.GOOGLE,
        model="gemini-pro",
        prompt=prompt,
        project_id="your-project",
        location="us-central1"
    )
    
    return response.content
```

### 使用量レポート

```python
from google.cloud import serviceusage_v1

client = serviceusage_v1.ServiceUsageClient()

# 使用量を報告
operation = client.generate_service_identity(
    request={
        "parent": "projects/your-project/services/openpic.googleapis.com"
    }
)

# メトリクスを記録
from google.cloud import monitoring_v3
monitoring_client = monitoring_v3.MetricServiceClient()

series = monitoring_v3.TimeSeries()
series.metric.type = "custom.googleapis.com/openpic/requests"
series.resource.type = "global"
point = series.points.add()
point.value.int64_value = 1000
point.interval.end_time.seconds = int(time.time())

monitoring_client.create_time_series(
    name=f"projects/your-project",
    time_series=[series]
)
```

---

## 🔄 マルチクラウド統合

### 統一されたセキュリティポリシー

```python
from openpic_sdk import SecureLLMClient, Provider

class MultiCloudSecureClient:
    """複数クラウドプロバイダーを統一されたセキュリティで管理"""
    
    def __init__(self, openpic_api_key: str, tenant_id: str):
        self.openpic = SecureLLMClient(openpic_api_key, tenant_id)
    
    async def call_best_available(self, prompt: str):
        """最も応答が速いプロバイダーを自動選択"""
        
        providers = [
            (Provider.OPENAI, "gpt-4"),
            (Provider.ANTHROPIC, "claude-3-opus"),
            (Provider.GOOGLE, "gemini-pro")
        ]
        
        # 並列で呼び出し、最初に返ってきたものを使用
        tasks = [
            self.openpic.call(provider, model, prompt)
            for provider, model in providers
        ]
        
        response = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        return response.result()
```

---

## 📊 コスト最適化

### 自動フェイルオーバー

```python
async def cost_optimized_call(prompt: str):
    """コスト最適化されたLLM呼び出し"""
    
    # まず安価なモデルを試す
    try:
        response = await openpic.call(
            provider=Provider.OPENAI,
            model="gpt-3.5-turbo",  # より安価
            prompt=prompt
        )
        
        # 品質チェック
        if response.quality_score > 0.8:
            return response
    except Exception:
        pass
    
    # フォールバック：高品質モデル
    return await openpic.call(
        provider=Provider.OPENAI,
        model="gpt-4",
        prompt=prompt
    )
```

### 使用量アラート

```python
# CloudWatch (AWS)
import boto3

cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_alarm(
    AlarmName='OpenPicHighUsage',
    MetricName='Requests',
    Namespace='OpenPic',
    Statistic='Sum',
    Period=3600,
    EvaluationPeriods=1,
    Threshold=100000,
    ComparisonOperator='GreaterThanThreshold',
    AlarmActions=['arn:aws:sns:us-east-1:123456789:alert-topic']
)
```

---

## 🔐 セキュリティベストプラクティス

### Secrets Manager統合

```python
# AWS Secrets Manager
import boto3
import json

secrets = boto3.client('secretsmanager', region_name='us-east-1')

def get_openpic_key():
    """Secrets Managerから安全にAPIキーを取得"""
    secret_value = secrets.get_secret_value(SecretId='openpic/api_key')
    return json.loads(secret_value['SecretString'])['api_key']

# 使用
openpic = SecureLLMClient(
    openpic_api_key=get_openpic_key(),
    tenant_id="my_company"
)
```

### VPC Endpoints (AWS)

```bash
# プライベート接続を作成
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxx \
  --service-name com.amazonaws.vpce.us-east-1.vpce-svc-openpic \
  --subnet-ids subnet-xxx \
  --security-group-ids sg-xxx
```

---

## 📈 モニタリング & ロギング

### CloudWatch Logs統合

```python
import boto3
import json

logs = boto3.client('logs')

def log_security_event(event: dict):
    """セキュリティイベントをCloudWatch Logsに記録"""
    logs.put_log_events(
        logGroupName='/openpic/security',
        logStreamName='threats',
        logEvents=[
            {
                'timestamp': int(time.time() * 1000),
                'message': json.dumps(event)
            }
        ]
    )
```

### Datadog統合

```python
from datadog import initialize, statsd

initialize(api_key='your_datadog_key')

# メトリクスを送信
statsd.increment('openpic.requests')
statsd.histogram('openpic.latency', response.latency_ms)
statsd.increment(f'openpic.threats.{threat.severity}')
```

---

## 🎯 サポート

- **ドキュメント**: https://docs.openpic.ai
- **サポート**: support@openpic.ai
- **Slack Community**: https://openpic-community.slack.com
- **GitHub**: https://github.com/evidai/Openpic

---

## 📝 ライセンス

Business Source License 1.1 (BSL 1.1)
- 内部使用・クライアントデプロイは無料
- SaaS提供には別途商用ライセンスが必要
- 2030年1月1日にApache 2.0へ自動移行
