#!/bin/bash
# =============================================================
# EC2 部署脚本 - Lark Integration Automation
# =============================================================

set -e

echo "=========================================="
echo "Lark Integration Automation - EC2 部署"
echo "=========================================="

# 配置区域
REGION="ap-southeast-1"
PROJECT_DIR="/opt/lark-integration-automation"
GITHUB_REPO="https://github.com/westlife613/lark-integration-automation.git"

# Step 1: 安装依赖
echo "[1/6] 安装系统依赖..."
sudo yum update -y
sudo yum install -y python3 python3-pip git

# Step 2: 克隆代码
echo "[2/6] 克隆代码..."
if [ -d "$PROJECT_DIR" ]; then
    echo "项目目录已存在，更新代码..."
    cd $PROJECT_DIR
    git pull
else
    sudo git clone $GITHUB_REPO $PROJECT_DIR
    sudo chown -R ec2-user:ec2-user $PROJECT_DIR
    cd $PROJECT_DIR
fi

# Step 3: 安装 Python 依赖
echo "[3/6] 安装 Python 依赖..."
cd $PROJECT_DIR
pip3 install -r requirements.txt --user

# Step 4: 部署 DynamoDB 表
echo "[4/6] 部署 DynamoDB 表..."
aws cloudformation deploy \
    --template-file infrastructure/dynamodb-table.yaml \
    --stack-name security-events-table \
    --region $REGION \
    --no-fail-on-empty-changeset || echo "DynamoDB 表已存在或无变更"

# Step 5: 提示配置 SSM 参数
echo "[5/6] 配置 SSM 参数..."
echo ""
echo "⚠️  请确保以下 SSM 参数已配置 (SecureString 类型):"
echo "   - lark-app-id"
echo "   - lark-app-secret"
echo "   - lark-chat-id"
echo ""
echo "如未配置，请运行以下命令 (替换 your-xxx 为实际值):"
echo ""
echo "aws ssm put-parameter --name 'lark-app-id' --value 'your-app-id' --type SecureString --region $REGION"
echo "aws ssm put-parameter --name 'lark-app-secret' --value 'your-secret' --type SecureString --region $REGION"
echo "aws ssm put-parameter --name 'lark-chat-id' --value 'your-chat-id' --type SecureString --region $REGION"
echo ""

# Step 6: 验证部署
echo "[6/6] 验证部署..."
echo ""
echo "✅ 代码部署完成！"
echo ""
echo "项目目录: $PROJECT_DIR"
echo "Python 版本: $(python3 --version)"
echo ""
echo "=========================================="
echo "后续步骤"
echo "=========================================="
echo ""
echo "1. 配置 SSM 参数 (如上所示)"
echo ""
echo "2. 部署 Lambda 函数:"
echo "   cd $PROJECT_DIR"
echo "   # 打包 Lambda"
echo "   zip -r lambda.zip src/ -x '*.pyc'"
echo "   # 上传到 S3 并创建 Lambda (或使用 AWS Console)"
echo ""
echo "3. 创建 EventBridge 规则监听 Security Hub findings"
echo ""
echo "4. 本地测试:"
echo "   cd $PROJECT_DIR"
echo "   python3 tests/test_event.py"
echo ""
