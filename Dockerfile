# note: never use the :latest tag in a production site
FROM golang:1-alpine AS builder

RUN set -eux \
    && apk --no-cache add --virtual build-dependencies upx cmake g++ make unzip curl git tzdata

RUN cp /usr/share/zoneinfo/Japan /etc/localtime

ARG APP_NAME=athenz_user_cert
ENV APP_NAME=${APP_NAME}
ARG VERSION=test
ENV VERSION=${VERSION}

WORKDIR ${GOPATH}/src/${APP_NAME}

COPY . .

RUN make \
    && mv "${GOPATH}/bin/${APP_NAME}" "/usr/bin/${APP_NAME}"

RUN /usr/bin/${APP_NAME} version

RUN apk del build-dependencies --purge \
    && rm -rf "${GOPATH}"

# Start From Alpine For Running Environment
FROM alpine

RUN apk add net-tools openssl

ARG APP_NAME=athenz_user_cert
ENV APP_NAME=${APP_NAME}

COPY --from=builder /usr/bin/${APP_NAME} /usr/bin/${APP_NAME}

ENTRYPOINT ["/usr/bin/${APP_NAME}"]

