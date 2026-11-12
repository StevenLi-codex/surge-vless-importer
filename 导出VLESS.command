#!/bin/zsh
set -eu
TOOL_DIR="${0:A:h}"
cd "$TOOL_DIR"
PYTHON_BIN="${VLESS_PYTHON:-/usr/bin/python3}"
if ! "$PYTHON_BIN" -c 'import sys; sys.path.insert(0,"vendor"); import yaml' >/dev/null 2>&1; then
  echo '首次运行：安装 YAML 解析依赖到工具目录。'
  if ! "$PYTHON_BIN" -m pip install --disable-pip-version-check --target "$TOOL_DIR/vendor" -r "$TOOL_DIR/requirements.txt"; then
    echo '依赖安装失败，请按照 README 配置 Python。按回车关闭。'
    read -r
    exit 1
  fi
fi
"$PYTHON_BIN" "$TOOL_DIR/convert.py" --dialog || result=$?
exit "${result:-0}"
