#!/bin/bash
# Rebuilds the code signature fixtures. Run on macOS (here: macOS 27.0.1, arm64,
# Xcode clang 21) in an empty scratch directory: `make-fixtures.sh <dir>`.
# Copy hello.c and ent.plist from this directory there first.
#
# The self-signed identity lives in a temporary keychain that is deleted again;
# the user's keychain search list is left as it was. The CMS signatures therefore
# chain to no anchor and carry no timestamp (`--timestamp=none`).
set -eu
cd "$1"

xcrun clang -arch arm64 -O1 -o linker-signed hello.c
cp linker-signed adhoc
codesign -s - -f --identifier org.darlinghq.test.adhoc adhoc
cp linker-signed adhoc-runtime-ent
codesign -s - -f -o runtime --entitlements ent.plist --digest-algorithm=sha1,sha256 \
	--identifier org.darlinghq.test.runtime adhoc-runtime-ent
xcrun clang -arch x86_64 -arch arm64 -O1 -o fat-adhoc hello.c
codesign -s - -f --identifier org.darlinghq.test.fat fat-adhoc
xcrun clang -arch x86_64 -arch arm64 -O1 -o fat-runtime hello.c
codesign -s - -f -o runtime --identifier org.darlinghq.test.fatruntime fat-runtime
cp linker-signed unsigned
codesign --remove-signature unsigned

KC="$PWD/fixtures.keychain-db"
before=$(security list-keychains -d user)
cat > cert.cnf <<'N'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = Darling Test Signer
OU = DTESTTEAM1
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
N
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 -config cert.cnf
openssl pkcs12 -export -inkey key.pem -in cert.pem -out id.p12 -passout pass:darling -name "Darling Test Signer"
security create-keychain -p darling "$KC"
# create-keychain adds the keychain to the search list; put the old list back
security list-keychains -d user -s $(echo "$before" | tr -d '"')
security unlock-keychain -p darling "$KC"
security import id.p12 -k "$KC" -P darling -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k darling "$KC" || true
cp linker-signed cms-signed
codesign -s "Darling Test Signer" --keychain "$KC" -f --timestamp=none \
	--identifier org.darlinghq.test.cms cms-signed
cp linker-signed cms-dual
codesign -s "Darling Test Signer" --keychain "$KC" -f --timestamp=none -o runtime \
	--entitlements ent.plist --digest-algorithm=sha1,sha256 \
	--identifier org.darlinghq.test.cmsdual cms-dual
security delete-keychain "$KC"
rm -f key.pem id.p12

for f in linker-signed adhoc adhoc-runtime-ent fat-adhoc fat-runtime cms-signed cms-dual unsigned; do
	echo "=== $f"
	codesign -dvvv "$f" 2>&1 | sed -e 's/^Executable=.*/Executable=<path>/' -e '/^Signed Time=/d'
	codesign -d --entitlements - --xml "$f" 2>/dev/null; echo
	if [ "$f" = fat-adhoc ] || [ "$f" = fat-runtime ]; then
		for a in x86_64 arm64; do
			echo "--- arch $a"
			codesign -dvvv --arch $a "$f" 2>&1 | sed -e 's/^Executable=.*/Executable=<path>/'
		done
	fi
	echo "--- verify"
	codesign --verify --strict -v "$f" 2>&1
done
