#!/bin/zsh

set -e

DEVICE_TYPES=("nano_sp" "flex" "stax")
NETWORKS=("mainnet" "testnet")

typeset -A SDK_ENV_VARS
SDK_ENV_VARS["nano_sp"]="NANOSP_SDK"
SDK_ENV_VARS["flex"]="FLEX_SDK"
SDK_ENV_VARS["stax"]="STAX_SDK"

typeset -A COIN_NAME
COIN_NAME["mainnet"]="BBNST"
COIN_NAME["testnet"]="BBNST_test"

typeset -A OUTPUT_PATH
OUTPUT_PATH["mainnet"]="installer/apdu"
OUTPUT_PATH["testnet"]="installer/apdu-test"

mkdir -p bin installer/apdu installer/apdu-test

echo "starting..."

for network in "${NETWORKS[@]}"; do
    echo ""
    echo "===== construct $network ====="
    for device in "${DEVICE_TYPES[@]}"; do
        sdk_env="${SDK_ENV_VARS["$device"]}"
        coin="${COIN_NAME["$network"]}"

        echo "--> construct $device (env: $sdk_env) / coin: $coin"

        docker exec -u 0 ledger-babylon-app-container bash -lc "\
            pip install --break-system-packages --upgrade typing_extensions && \
            git submodule update --init --recursive && \
            export BOLOS_SDK=\$$sdk_env && \
            make -C . -B -j DEBUG=0 COIN=$coin \
        "

        src_path="bin/app.apdu"
        dest_path="${OUTPUT_PATH["$network"]}/${device}.apdu"

        if [ -f "$src_path" ]; then
            echo "cp $src_path to $dest_path"
            cp "$src_path" "$dest_path"
        else
            echo "error: not found $src_path"
            exit 1
        fi
    done
done

echo "✅ Firmware build finished. All .apdu files copied."

echo ""
echo "🚀 Step 2: Building installer..."
cd installer
./make_installer.sh
cd ..
echo ""
echo "✅ All steps completed successfully."