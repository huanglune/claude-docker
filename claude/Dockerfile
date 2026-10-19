# Claude Code does not need a CUDA userland. The NVIDIA Container Toolkit
# injects the driver libraries and nvidia-smi into this generic Ubuntu image
# at container start (see gpus/all and NVIDIA_DRIVER_CAPABILITIES in compose).
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG CLAUDE_USER=claude
ARG CLAUDE_UID=1000
ARG CLAUDE_GID=1000
ARG CONTAINER_TZ=America/Los_Angeles

ENV DEBIAN_FRONTEND=noninteractive
ARG CLAUDE_EXTRA_APT_PACKAGES=""

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl git gnupg iproute2 less locales openssh-client \
      procps python3 sudo tini tzdata wget; \
    rm -rf /var/lib/apt/lists/*; \
    sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen; \
    locale-gen

RUN set -eux; \
    if [ -n "${CLAUDE_EXTRA_APT_PACKAGES}" ]; then \
      apt-get update; \
      printf '%s\n' "${CLAUDE_EXTRA_APT_PACKAGES}" \
        | xargs -r apt-get install -y --no-install-recommends; \
      rm -rf /var/lib/apt/lists/*; \
    fi

RUN set -eux; \
    test -f "/usr/share/zoneinfo/${CONTAINER_TZ}"; \
    ln -snf "/usr/share/zoneinfo/${CONTAINER_TZ}" /etc/localtime; \
    echo "${CONTAINER_TZ}" > /etc/timezone

RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    npm install -g @anthropic-ai/claude-code

RUN set -eux; \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh; \
    uv --version

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends zsh; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    groupadd --gid "${CLAUDE_GID}" "${CLAUDE_USER}"; \
    useradd --uid "${CLAUDE_UID}" --gid "${CLAUDE_GID}" \
      --create-home --shell /usr/bin/zsh "${CLAUDE_USER}"; \
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${CLAUDE_USER}" > /etc/sudoers.d/claude-user; \
    chmod 0440 /etc/sudoers.d/claude-user; \
    visudo -cf /etc/sudoers.d/claude-user; \
    mkdir -p "/home/${CLAUDE_USER}/workspace" "/home/${CLAUDE_USER}/md1"; \
    chown -R "${CLAUDE_UID}:${CLAUDE_GID}" "/home/${CLAUDE_USER}"

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TZ="${CONTAINER_TZ}" \
    HOME="/home/${CLAUDE_USER}" \
    USER="${CLAUDE_USER}" \
    LOGNAME="${CLAUDE_USER}" \
    PATH="/home/${CLAUDE_USER}/.local/bin:/usr/local/nvidia/bin:/usr/local/cuda/bin:/usr/local/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/nvidia/lib:/usr/local/nvidia/lib64"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
