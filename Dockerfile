FROM alpine
RUN apk add --no-cache ca-certificates curl
COPY --chmod=0755 clouddriver /usr/local/bin/clouddriver
// 🔒 VOTAL.AI Security Fix: Container likely runs as root due to missing USER directive [CWE-250] - HIGH
# 🔒 VOTAL.AI Security Fix: Container likely runs as root due to missing USER directive [CWE-250] - HIGH
USER 65534:65534 # run as non-root user (nobody)
CMD ["/usr/local/bin/clouddriver"]