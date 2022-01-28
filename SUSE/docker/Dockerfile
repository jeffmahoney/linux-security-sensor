FROM opensuse/tumbleweed

# Need to build on SLE first -- it's mostly static but depends on glibc
#FROM registry.suse.com/suse/sle15:latest

VOLUME /data
VOLUME /logs
VOLUME /config

# API
EXPOSE 8801

# GUI
EXPOSE 8889

# Frontend
EXPOSE 8000

# Monitoring
EXPOSE 8003

COPY entry-point.sh generate-config.sh obs-signing-key.key /
COPY init-config.json /etc/velociraptor/
RUN rpm --import /obs-signing-key.key
RUN zypper -q ar obs://security:sensor/ "obs://security/sensor"
RUN zypper -q --non-interactive refresh
RUN zypper -q --non-interactive install velociraptor

CMD /entry-point.sh
