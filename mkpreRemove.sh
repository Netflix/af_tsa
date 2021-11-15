#!/bin/bash

cat <<EOF
#!/bin/bash
dkms remove -m af_tsa -v ${VERSION} --all || true
EOF
