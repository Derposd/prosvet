# Built by GoReleaser (dockers_v2): the binary is placed in $TARGETPLATFORM/.
# distroless/static provides CA certificates (needed to judge certificate trust).
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/prosvet /usr/bin/prosvet
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/prosvet"]
CMD ["scan", "--yes"]
