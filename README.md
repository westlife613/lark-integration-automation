# Lark Integration Automation

AWS 安全事件 (SecurityHub / GuardDuty) 集成 Lark 通知和 DynamoDB 存储的 Lambda 项目。

## 功能

- 接收 AWS SecurityHub / GuardDuty 安全事件
- 查询 CloudTrail 获取操作者信息
- 通过 Lark API 发送通知并 @相关人员
- 将事件存储到 DynamoDB（支持幂等写入）

## 项目结构

```
lark-integration-automation/
├── src/
│   ├── handlers/
│   │   └── security_groups/
│   │       └── lambda_function.py      # SecurityHub SG 告警处理
│   └── shared/
│       ├── cloudtrail_helper.py        # CloudTrail 查询助手
│       ├── unified_handler.py          # 统一事件处理器
│       └── db_handler.py               # DynamoDB 操作助手
├── infrastructure/
│   └── dynamodb-table.yaml             # DynamoDB CloudFormation 模板
├── tests/
│   └── test_event.py                   # 测试脚本
├── requirements.txt
└── README.md
```

## 部署

### 1. 创建 DynamoDB 表

```bash
aws cloudformation deploy \
  --template-file infrastructure/dynamodb-table.yaml \
  --stack-name security-events-table \
  --region ap-southeast-1
```

### 2. 配置 SSM 参数

```bash
aws ssm put-parameter --name "SYD-Audit-Security-Automation-PROD-Parameter-Lark-APP-ID" --value "your-app-id" --type SecureString
aws ssm put-parameter --name "SYD-Audit-Security-Automation-PROD-Parameter-Lark-APP-Secret" --value "your-secret" --type SecureString
aws ssm put-parameter --name "SYD-Audit-Security-Automation-PROD-Parameter-Lark-Chat-ID" --value "your-chat-id" --type SecureString
```

### 3. 部署 Lambda

打包并部署到 AWS Lambda，配置 EventBridge 规则监听 SecurityHub findings。

## 本地测试

```bash
cd src
export PYTHONPATH=$(pwd)/shared
python tests/test_event.py
```

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| DDB_TABLE | DynamoDB 表名 | security-events |
| AWS_REGION | AWS 区域 | us-east-1 |
| DYNAMODB_ENDPOINT | DynamoDB 端点（本地测试用） | http://localhost:8001 |
