PROJECT = acorn128
PROJECT_DESCRIPTION = ACORN-128 (v3) AEAD Cipher NIF for Erlang and Elixir
PROJECT_VERSION = 0.0.1

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-test

DOCKER_OTP_VERSION ?= 22.2.1

docker-build::
	$(gen_verbose) docker build \
		-t docker-otp-${DOCKER_OTP_VERSION} \
		-f priv/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		priv

docker-load::
	$(gen_verbose) docker load \
		-i "docker-otp-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "docker-otp-${DOCKER_OTP_VERSION}/image.tar" \
		docker-otp-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/acorn128" "docker-otp-${DOCKER_OTP_VERSION}" \
		sh -c 'cd acorn128 \
		&& CC=clang-9 CXX=clang++-9 make tests'
