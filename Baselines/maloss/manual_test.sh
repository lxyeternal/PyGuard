#!/bin/bash
# Maloss 手动测试脚本 - 模拟Hercule的disposable container策略
# 目标：挂载已下载的包，手动执行分析，验证流程

set -e  # 遇到错误立即退出

echo "=================================================="
echo "  Maloss Manual Test - Disposable Container"
echo "=================================================="
echo ""

# ==================== 配置 ====================
# 根据你的Hercule脚本路径推断
HOST_BENIGN_DIR="/home2/wenbo/Documents/PyPIAgent/Dataset/latest/zip_benign"
HOST_MALWARE_DIR="/home2/wenbo/Documents/PyPIAgent/Dataset/latest/zip_malware"

# Maloss元数据和结果目录
METADATA_DIR="/tmp/maloss_test_metadata"
RESULT_DIR="/tmp/maloss_test_result"

# 容器配置
CONTAINER_NAME="maloss_test_$(date +%s)"
IMAGE_NAME="maloss:latest"
MEMORY_LIMIT="6g"

# 容器内路径
CONTAINER_BENIGN="/data/benign"
CONTAINER_MALWARE="/data/malware"
CONTAINER_METADATA="/metadata"
CONTAINER_RESULT="/result"

echo "📁 配置信息："
echo "  - 良性包目录: $HOST_BENIGN_DIR"
echo "  - 恶意包目录: $HOST_MALWARE_DIR"
echo "  - 元数据目录: $METADATA_DIR"
echo "  - 结果目录: $RESULT_DIR"
echo "  - 容器名称: $CONTAINER_NAME"
echo "  - 内存限制: $MEMORY_LIMIT"
echo ""

# ==================== 步骤1: 检查镜像 ====================
echo "🔍 [步骤1] 检查Docker镜像..."
if ! docker image inspect $IMAGE_NAME &> /dev/null; then
    echo "❌ 镜像 $IMAGE_NAME 不存在！"
    echo "请先构建镜像："
    echo "  cd /home2/wenbo/Documents/PyPIAgent/Tools/maloss"
    echo "  sudo docker build -t maloss:latest ."
    exit 1
fi
echo "✅ 镜像已存在"
echo ""

# ==================== 步骤2: 创建测试目录 ====================
echo "📁 [步骤2] 创建测试目录..."
mkdir -p "$METADATA_DIR/python"
mkdir -p "$RESULT_DIR/python"
chmod -R 777 "$METADATA_DIR"
chmod -R 777 "$RESULT_DIR"
echo "✅ 目录创建完成"
echo ""

# ==================== 步骤3: 检查测试包 ====================
echo "📦 [步骤3] 检查测试包..."

# 从良性包中找一个小包测试
TEST_BENIGN_PKG=""
if [ -d "$HOST_BENIGN_DIR" ]; then
    TEST_BENIGN_PKG=$(find "$HOST_BENIGN_DIR" -name "*.tar.gz" -o -name "*.tgz" | head -1)
fi

# 从恶意包中找一个测试
TEST_MALWARE_PKG=""
if [ -d "$HOST_MALWARE_DIR" ]; then
    TEST_MALWARE_PKG=$(find "$HOST_MALWARE_DIR" -name "*.tar.gz" -o -name "*.tgz" | head -1)
fi

if [ -z "$TEST_BENIGN_PKG" ] && [ -z "$TEST_MALWARE_PKG" ]; then
    echo "❌ 没有找到测试包！"
    echo "请检查路径："
    echo "  - $HOST_BENIGN_DIR"
    echo "  - $HOST_MALWARE_DIR"
    exit 1
fi

if [ -n "$TEST_BENIGN_PKG" ]; then
    echo "✅ 找到良性测试包: $(basename $TEST_BENIGN_PKG)"
fi
if [ -n "$TEST_MALWARE_PKG" ]; then
    echo "✅ 找到恶意测试包: $(basename $TEST_MALWARE_PKG)"
fi
echo ""

# ==================== 步骤4: 创建容器 ====================
echo "🔨 [步骤4] 创建Maloss容器..."
echo "执行命令："
echo "docker run -d \\"
echo "  --name $CONTAINER_NAME \\"
echo "  --memory $MEMORY_LIMIT \\"
echo "  --memory-swap $MEMORY_LIMIT \\"
echo "  -v $HOST_BENIGN_DIR:$CONTAINER_BENIGN:ro \\"
echo "  -v $HOST_MALWARE_DIR:$CONTAINER_MALWARE:ro \\"
echo "  -v $METADATA_DIR:$CONTAINER_METADATA \\"
echo "  -v $RESULT_DIR:$CONTAINER_RESULT \\"
echo "  $IMAGE_NAME \\"
echo "  tail -f /dev/null"
echo ""

docker run -d \
  --name "$CONTAINER_NAME" \
  --memory "$MEMORY_LIMIT" \
  --memory-swap "$MEMORY_LIMIT" \
  -v "$HOST_BENIGN_DIR:$CONTAINER_BENIGN:ro" \
  -v "$HOST_MALWARE_DIR:$CONTAINER_MALWARE:ro" \
  -v "$METADATA_DIR:$CONTAINER_METADATA" \
  -v "$RESULT_DIR:$CONTAINER_RESULT" \
  "$IMAGE_NAME" \
  tail -f /dev/null

echo "✅ 容器创建成功: $CONTAINER_NAME"
echo ""

# 等待容器启动
sleep 2

# ==================== 步骤5: 验证挂载 ====================
echo "🔍 [步骤5] 验证数据挂载..."
echo ""

echo "检查容器内良性包目录："
docker exec "$CONTAINER_NAME" bash -c "ls -lh $CONTAINER_BENIGN | head -10"
echo ""

echo "检查容器内恶意包目录："
docker exec "$CONTAINER_NAME" bash -c "ls -lh $CONTAINER_MALWARE | head -10"
echo ""

# ==================== 步骤6: 检查Maloss命令 ====================
echo "🔍 [步骤6] 检查Maloss环境..."
echo ""

echo "检查Python版本："
docker exec "$CONTAINER_NAME" python3 --version
echo ""

echo "检查Maloss路径："
docker exec "$CONTAINER_NAME" bash -c "ls -la /home/maloss/" || true
echo ""

echo "检查detector.py："
docker exec "$CONTAINER_NAME" bash -c "ls -la /home/maloss/main/detector.py" || true
docker exec "$CONTAINER_NAME" bash -c "ls -la /home/maloss/src/main.py" || true
echo ""

# ==================== 步骤7: 手动测试分析 ====================
echo "=================================================="
echo "  容器已启动！现在可以手动测试了"
echo "=================================================="
echo ""
echo "🎯 手动测试步骤："
echo ""
echo "1️⃣  进入容器："
echo "   docker exec -it $CONTAINER_NAME bash"
echo ""
echo "2️⃣  查看挂载的包（良性）："
echo "   ls -lh $CONTAINER_BENIGN"
echo ""
echo "3️⃣  查看挂载的包（恶意）："
echo "   ls -lh $CONTAINER_MALWARE"
echo ""

# 选择一个测试包
if [ -n "$TEST_MALWARE_PKG" ]; then
    TEST_PKG="$TEST_MALWARE_PKG"
    TEST_KIND="malware"
    CONTAINER_PKG="$CONTAINER_MALWARE/$(basename $TEST_PKG)"
else
    TEST_PKG="$TEST_BENIGN_PKG"
    TEST_KIND="benign"
    CONTAINER_PKG="$CONTAINER_BENIGN/$(basename $TEST_PKG)"
fi

PKG_NAME=$(basename "$TEST_PKG" .tar.gz)

echo "4️⃣  测试包信息："
echo "   主机路径: $TEST_PKG"
echo "   容器路径: $CONTAINER_PKG"
echo "   包名称: $PKG_NAME"
echo ""

echo "5️⃣  执行静态分析（方法1 - 使用src/main.py）："
echo "   cd /home/maloss/src"
echo "   python3 main.py taint \\"
echo "     -n $PKG_NAME \\"
echo "     -i $CONTAINER_PKG \\"
echo "     -d $CONTAINER_METADATA \\"
echo "     -o $CONTAINER_RESULT \\"
echo "     -l python \\"
echo "     -c /home/maloss/config/astgen_python_smt.config"
echo ""

echo "6️⃣  执行静态分析（方法2 - 使用main/detector.py）："
echo "   cd /home/maloss/main"
echo "   python3 detector.py taint_local \\"
echo "     -n $PKG_NAME \\"
echo "     -i $CONTAINER_PKG \\"
echo "     -d $CONTAINER_METADATA \\"
echo "     -o $CONTAINER_RESULT \\"
echo "     -l python \\"
echo "     -c /home/maloss/config/astgen_python_smt.config \\"
echo "     --native"
echo ""

echo "7️⃣  查看结果："
echo "   ls -lh $CONTAINER_RESULT/python/$PKG_NAME/"
echo "   cat $CONTAINER_RESULT/python/$PKG_NAME/taint_result.json"
echo ""

echo "8️⃣  在主机上查看结果："
echo "   tree $RESULT_DIR"
echo "   cat $RESULT_DIR/python/$PKG_NAME/taint_result.json"
echo ""

# ==================== 自动执行一次测试 ====================
echo "=================================================="
echo "  自动执行一次测试分析"
echo "=================================================="
echo ""

echo "📦 测试包: $PKG_NAME"
echo "🚀 开始分析..."
echo ""

# 尝试方法1
echo "尝试使用 src/main.py..."
docker exec "$CONTAINER_NAME" bash -c "
cd /home/maloss/src && \
python3 main.py taint \
  -n '$PKG_NAME' \
  -i '$CONTAINER_PKG' \
  -d '$CONTAINER_METADATA' \
  -o '$CONTAINER_RESULT' \
  -l python \
  -c /home/maloss/config/astgen_python_smt.config 2>&1 | tee /tmp/maloss_test.log
" || {
    echo "❌ 方法1失败，查看日志..."
    docker exec "$CONTAINER_NAME" cat /tmp/maloss_test.log || true
    echo ""
    echo "尝试方法2..."
}

echo ""
echo "=================================================="
echo "  测试完成！"
echo "=================================================="
echo ""

echo "📊 检查输出结果："
if [ -d "$RESULT_DIR/python/$PKG_NAME" ]; then
    echo "✅ 找到结果目录"
    tree "$RESULT_DIR/python/$PKG_NAME" || ls -lR "$RESULT_DIR/python/$PKG_NAME"
else
    echo "⚠️  结果目录不存在，可能分析失败"
    echo "请手动进入容器调试："
    echo "  docker exec -it $CONTAINER_NAME bash"
fi
echo ""

echo "🔧 调试命令："
echo "  - 查看容器日志: docker logs $CONTAINER_NAME"
echo "  - 进入容器: docker exec -it $CONTAINER_NAME bash"
echo "  - 查看分析日志: docker exec $CONTAINER_NAME cat /tmp/maloss_test.log"
echo ""

echo "🗑️  清理容器："
echo "  docker rm -f $CONTAINER_NAME"
echo ""

echo "💡 提示："
echo "  容器将保持运行，你可以手动进入测试"
echo "  测试完成后执行清理命令"
echo ""

