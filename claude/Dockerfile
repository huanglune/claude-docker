# CPU image. Claude Code runs on generic Ubuntu LTS and does not request a GPU.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ARG CLAUDE_USER=claude
ARG CLAUDE_UID=1000
ARG CLAUDE_GID=1000
ARG CONTAINER_TZ=America/Los_Angeles
ARG CLAUDE_EXTRA_APT_PACKAGES=""

ENV DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
      cp -a /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.orig; \
      sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' \
        -e 's|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' \
        -e 's|http://ports.ubuntu.com/ubuntu-ports|http://mirrors.aliyun.com/ubuntu-ports|g' \
        /etc/apt/sources.list.d/ubuntu.sources; \
    else \
      cp -a /etc/apt/sources.list /etc/apt/sources.list.orig; \
      sed -i \
        -e 's|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' \
        -e 's|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' \
        -e 's|http://ports.ubuntu.com/ubuntu-ports|http://mirrors.aliyun.com/ubuntu-ports|g' \
        /etc/apt/sources.list; \
    fi

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl git gnupg iproute2 iptables less locales \
      openssh-client procps python3 sudo tini tzdata util-linux wget zsh; \
    rm -rf /var/lib/apt/lists/*; \
    sed -i 's/^# *en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen; \
    locale-gen; \
    test -f "/usr/share/zoneinfo/${CONTAINER_TZ}"; \
    ln -snf "/usr/share/zoneinfo/${CONTAINER_TZ}" /etc/localtime; \
    echo "${CONTAINER_TZ}" > /etc/timezone

RUN set -eux; \
    if [ -n "${CLAUDE_EXTRA_APT_PACKAGES}" ]; then \
      apt-get update; \
      printf '%s\n' "${CLAUDE_EXTRA_APT_PACKAGES}" \
        | xargs -r apt-get install -y --no-install-recommends; \
      rm -rf /var/lib/apt/lists/*; \
    fi

RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    npm install -g @anthropic-ai/claude-code; \
    npm cache clean --force

RUN set -eux; \
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh; \
    uv --version

RUN set -eux; \
    git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git /usr/local/share/oh-my-zsh; \
    git clone --depth=1 https://github.com/romkatv/powerlevel10k.git \
      /usr/local/share/oh-my-zsh/custom/themes/powerlevel10k; \
    git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions.git \
      /usr/local/share/oh-my-zsh/custom/plugins/zsh-autosuggestions; \
    git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git \
      /usr/local/share/oh-my-zsh/custom/plugins/zsh-syntax-highlighting; \
    git clone --depth=1 https://github.com/MichaelAquilina/zsh-you-should-use.git \
      /usr/local/share/oh-my-zsh/custom/plugins/you-should-use; \
    GITSTATUS_CACHE_DIR=/usr/local/share/oh-my-zsh/custom/themes/powerlevel10k/gitstatus/usrbin \
      /usr/local/share/oh-my-zsh/custom/themes/powerlevel10k/gitstatus/install; \
    chmod -R a+rX /usr/local/share/oh-my-zsh

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources.orig ]; then \
      mv -f /etc/apt/sources.list.d/ubuntu.sources.orig /etc/apt/sources.list.d/ubuntu.sources; \
    elif [ -f /etc/apt/sources.list.orig ]; then \
      mv -f /etc/apt/sources.list.orig /etc/apt/sources.list; \
    fi

COPY zshrc /etc/skel/.zshrc
COPY zshenv.snippet /usr/local/share/claude-docker/zshenv.snippet
COPY network-guard.sh /usr/local/bin/claude-network-guard.sh
COPY entrypoint.sh /usr/local/bin/claude-entrypoint.sh
COPY claude-exec.sh /usr/local/bin/claude-exec
RUN chmod 0555 /usr/local/bin/claude-network-guard.sh /usr/local/bin/claude-entrypoint.sh /usr/local/bin/claude-exec && \
    cat /usr/local/share/claude-docker/zshenv.snippet >> /etc/zsh/zshenv

# Ubuntu 24.04 ships a default `ubuntu` user (uid/gid 1000); remove it if it
# conflicts with the target account identity. macOS `staff` is gid 20 (`dialout`).
RUN set -eux; \
    if id -u ubuntu >/dev/null 2>&1 && [ "${CLAUDE_USER}" != "ubuntu" ]; then \
      userdel -r ubuntu; \
    fi; \
    if getent group "${CLAUDE_GID}" >/dev/null; then \
      echo "gid ${CLAUDE_GID} already exists; reusing it for ${CLAUDE_USER}"; \
    elif getent group "${CLAUDE_USER}" >/dev/null; then \
      echo "group name ${CLAUDE_USER} exists with a different gid" >&2; \
      exit 1; \
    else \
      groupadd --gid "${CLAUDE_GID}" "${CLAUDE_USER}"; \
    fi; \
    if getent passwd "${CLAUDE_UID}" >/dev/null; then \
      echo "uid ${CLAUDE_UID} already exists" >&2; \
      exit 1; \
    fi; \
    if getent passwd "${CLAUDE_USER}" >/dev/null; then \
      echo "user ${CLAUDE_USER} already exists" >&2; \
      exit 1; \
    fi; \
    useradd --uid "${CLAUDE_UID}" --gid "${CLAUDE_GID}" \
      --create-home --shell /usr/bin/zsh "${CLAUDE_USER}"; \
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${CLAUDE_USER}" > /etc/sudoers.d/claude-user; \
    chmod 0440 /etc/sudoers.d/claude-user; \
    visudo -cf /etc/sudoers.d/claude-user; \
    mkdir -p "/home/${CLAUDE_USER}/workspace"; \
    chown -R "${CLAUDE_UID}:${CLAUDE_GID}" "/home/${CLAUDE_USER}"

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TZ="${CONTAINER_TZ}" \
    HOME="/home/${CLAUDE_USER}" \
    USER="${CLAUDE_USER}" \
    LOGNAME="${CLAUDE_USER}" \
    PATH="/home/${CLAUDE_USER}/.local/bin:/usr/local/bin:${PATH}"

ENTRYPOINT ["/usr/local/bin/claude-entrypoint.sh"]
CMD ["sleep", "infinity"]
