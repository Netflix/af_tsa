#!/bin/bash

cat <<EOF
#!/bin/bash
dkms add -m af_tsa -v ${VERSION}
dkms build -m af_tsa -v ${VERSION} && dkms install -m af_tsa -v ${VERSION} || true
EOF
