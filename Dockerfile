FROM scratch
ARG RUST_TARGET_DIR 

COPY ${RUST_TARGET_DIR}/cd-webhooks-forwarder /

CMD [ "/cd-webhooks-forwarder" ]

