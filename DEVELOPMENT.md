# Development and Debugging Guide

This guide provides detailed instructions for setting up a development environment, building the Babylon Ledger app, and running it in the Speculos emulator.

## Overview

The Speculos emulator comes **pre-installed** in the Docker container `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest`, so no additional installation is required.

**What is Speculos?**
Speculos is Ledger's official emulator that simulates Ledger devices (Nano S+, Nano X, Stax, Flex) on your computer. It provides a GUI interface and API for testing Ledger applications without physical hardware.

## Docker Setup

### Stop and Start Container

Stop and remove any existing container:
```shell
docker container stop ledger-babylon-app-container
docker container rm ledger-babylon-app-container
```

Start the Docker container:
```shell
docker run -p 3355:5000 --user $(id -u):$(id -g) --privileged -e DISPLAY='host.docker.internal:0' -v '/tmp/.X11-unix:/tmp/.X11-unix' -v '<your code path>:/app' -t -d --name ledger-babylon-app-container ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

Example with specific path:
```shell
docker run -p 3355:5000 --user $(id -u):$(id -g) --privileged -e DISPLAY='host.docker.internal:0' -v '/tmp/.X11-unix:/tmp/.X11-unix' -v "$HOME/Documents/babylonchain-io/repo/staking/ledger-babylon-app:/app" -t -d --name ledger-babylon-app-container ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

### Docker Flags Explanation

- `-p 3355:5000`: Maps port 5000 inside the container to port 3355 on the host (for Speculos web interface)
- `--user $(id -u):$(id -g)`: Runs container with your current user ID and group ID to avoid permission issues
- `--privileged`: Grants extended privileges to the container (needed for hardware access)
- `-e DISPLAY='host.docker.internal:0'`: Sets display environment variable for GUI applications (macOS)
- `-v '/tmp/.X11-unix:/tmp/.X11-unix'`: Mounts X11 socket for GUI display
- `-v '<your code path>:/app'`: Mounts your local code directory to `/app` inside the container
- `-t`: Allocates a pseudo-TTY
- `-d`: Runs container in detached mode (background)
- `--name ledger-babylon-app-container`: Assigns a name to the container for easy reference

## Prerequisites by Platform

### macOS

1. Install required dependencies:
   ```shell
   brew install qt
   brew install --cask xquartz
   ```

2. Configure XQuartz:
   - Allow connections from network clients in XQuartz settings
   - **Important:** Restart XQuartz after changing settings
   - Run `xhost +127.0.0.1` in XQuartz terminal

### Linux (Ubuntu/Debian)

1. Install required dependencies:
   ```shell
   sudo apt update
   sudo apt install -y qt5-default libqt5gui5 x11-xserver-utils
   ```

2. Configure X11 forwarding:
   ```shell
   # Allow local connections to X server
   xhost +local:docker
   
   # Or allow specific localhost access
   xhost +127.0.0.1
   ```

3. **Note:** On most Linux distributions, X11 server runs by default, so no additional setup is needed.

### Linux Docker Command Modification

For Linux, use this Docker command instead (note the different DISPLAY variable):

```shell
docker run -p 3355:5000 --user $(id -u):$(id -g) --privileged \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v "$HOME/Documents/babylonchain-io/repo/staking/ledger-babylon-app:/app" \
  -t -d --name ledger-babylon-app-container \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

### Windows

1. Install and configure an X11 server:
   - Download and install [VcXsrv](https://sourceforge.net/projects/vcxsrv/)
   - Launch VcXsrv with "Disable access control" checked
   - Use `host.docker.internal:0.0` as DISPLAY value

2. Docker command for Windows (PowerShell):
   ```shell
   docker run -p 3355:5000 --privileged `
     -e DISPLAY="host.docker.internal:0.0" `
     -v "$PWD:/app" `
     -t -d --name ledger-babylon-app-container `
     ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
   ```

## Build Application

Choose your target device by setting the appropriate `BOLOS_SDK` environment variable:

### Build for Ledger Flex
```shell
docker exec -u 0 ledger-babylon-app-container bash -lc "\
  pip install --break-system-packages --upgrade typing_extensions && \
  git submodule update --init --recursive && \
  export BOLOS_SDK=\$FLEX_SDK && \
  make -C . -B -j DEBUG=1 COIN=BBNST_test \
"
```

### Build for Ledger Stax
```shell
docker exec -u 0 ledger-babylon-app-container bash -lc "\
  pip install --break-system-packages --upgrade typing_extensions && \
  git submodule update --init --recursive && \
  export BOLOS_SDK=\$STAX_SDK && \
  make -C . -B -j DEBUG=1 COIN=BBNST_test \
"
```

### Build for Ledger Nano X
```shell
docker exec -u 0 ledger-babylon-app-container bash -lc "\
  pip install --break-system-packages --upgrade typing_extensions && \
  git submodule update --init --recursive && \
  export BOLOS_SDK=\$NANOX_SDK && \
  make -C . -B -j DEBUG=1 COIN=BBNST_test \
"
```

### Build for Ledger Nano S+
```shell
docker exec -u 0 ledger-babylon-app-container bash -lc "\
  pip install --break-system-packages --upgrade typing_extensions && \
  git submodule update --init --recursive && \
  export BOLOS_SDK=\$NANOSP_SDK && \
  make -C . -B -j DEBUG=1 COIN=BBNST_test \
"
```

### Build Flags Explanation

- `docker exec -u 0`: Execute command in container as root user (needed for pip install)
- `bash -lc`: Run bash as login shell with command
- `pip install --break-system-packages --upgrade typing_extensions`: Install required Python dependencies
- `git submodule update --init --recursive`: Initialize and update Git submodules
- `export BOLOS_SDK=$<DEVICE>_SDK`: Set the SDK environment variable for target device
- `make -C . -B -j`: Build the application
  - `-C .`: Change to current directory
  - `-B`: Force rebuild (ignore timestamps)
  - `-j`: Enable parallel compilation
- `DEBUG=1`: Enable debug mode with additional logging
- `COIN=BBNST_test`: Set coin type to Babylon testnet

## Running the Emulator

Enter the Docker container:
```shell
docker exec -it -u 0 ledger-babylon-app-container bash
```

### Emulator Commands for Different Models

#### Ledger Flex
```shell
# Default 24-phrase seed
speculos --model flex build/flex/bin/app.elf

# Custom seed phrase
speculos --model flex build/flex/bin/app.elf --seed "tourist swap proof boost broccoli destroy deer immune capable sheriff spray tower"

# With API server enabled
speculos --model flex build/flex/bin/app.elf --api-port 5000
```

#### Ledger Stax  
```shell
# Default 24-phrase seed
speculos --model stax build/stax/bin/app.elf

# Custom seed phrase
speculos --model stax build/stax/bin/app.elf --seed "tourist swap proof boost broccoli destroy deer immune capable sheriff spray tower"

# With API server enabled
speculos --model stax build/stax/bin/app.elf --api-port 5000
```

#### Ledger Nano X
```shell
# Default 24-phrase seed
speculos --model nanox build/nanox/bin/app.elf

# Custom seed phrase
speculos --model nanox build/nanox/bin/app.elf --seed "tourist swap proof boost broccoli destroy deer immune capable sheriff spray tower"

# With API server enabled
speculos --model nanox build/nanox/bin/app.elf --api-port 5000
```

#### Ledger Nano S+
```shell
# Default 24-phrase seed
speculos --model nanosp build/nanosp/bin/app.elf

# Custom seed phrase
speculos --model nanosp build/nanosp/bin/app.elf --seed "tourist swap proof boost broccoli destroy deer immune capable sheriff spray tower"

# With API server enabled
speculos --model nanosp build/nanosp/bin/app.elf --api-port 5000
```

### Speculos Flags Explanation

- `--model <model>`: Specify the Ledger device model to emulate (flex, stax, nanox, nanosp)
- `--seed "<mnemonic>"`: Set a custom 24-word seed phrase (if not provided, uses default)
- `--api-port <port>`: Enable HTTP API server on specified port (default 5000) for automation
- `--display headless`: Run without GUI (useful for CI/CD)
- `--button-port <port>`: Set port for button automation API
- `--automation <file>`: Load automation script for testing

### Common Speculos Options

```shell
# Run in headless mode (no GUI)
speculos --model flex build/flex/bin/app.elf --display headless

# Enable all API ports for testing
speculos --model flex build/flex/bin/app.elf --api-port 5000 --button-port 5001

# Load with automation file
speculos --model flex build/flex/bin/app.elf --automation tests/automations/my-test.json
```

## Troubleshooting

### Common Issues

1. **GUI not showing (macOS)**: Ensure XQuartz is restarted and `xhost +127.0.0.1` is run
2. **Permission errors**: Check that `--user $(id -u):$(id -g)` is included in Docker command
3. **Build failures**: Ensure git submodules are updated with `git submodule update --init --recursive`
4. **Container not found**: Check that the container name matches in all commands

### Useful Commands

```shell
# Check running containers
docker ps

# View container logs
docker logs ledger-babylon-app-container

# Stop container
docker stop ledger-babylon-app-container

# Remove container
docker rm ledger-babylon-app-container

# Access container shell
docker exec -it ledger-babylon-app-container bash
```

## Additional Resources

- [Speculos Documentation](https://github.com/LedgerHQ/speculos)
- [Original Bitcoin app repository](https://github.com/LedgerHQ/app-bitcoin-new)
- [Ledger Developer Tools](https://github.com/LedgerHQ/ledger-app-builder)
