FROM osixia/openldap:1.5.0

# Copy custom LDIF files
COPY bootstrap/ldif/custom /container/service/slapd/assets/config/bootstrap/ldif/custom

# Ensure proper permissions
RUN chown -R openldap:openldap /container/service/slapd/assets/config/bootstrap/ldif/custom