#!/usr/bin/env bash

VERSION=4.0.1
SCRIPT=`basename "$0"`
APPNAME="My App"
APPICONS="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns"
OSX_VERSION=`sw_vers -productVersion`
PWD=`pwd`

function usage {
	cat <<EOF
$SCRIPT v${VERSION} for for Mac OS X - https://gist.github.com/oubiwann/453744744da1141ccc542ff75b47e0cf
Usage:
  $SCRIPT [options]
Options:
  -h, --help 		Prints this help message, then exits
  -s, --script		Name of the script to 'appify' (required)
  -n, --name 		Name of the application (default "$APPNAME")
  -i, --icons		Name of the icons file to use when creating the app
                        (defaults to $APPICONS)
  -d, --document	Name of the document file to add as a resource
  -p, --persistence Name of the LaunchAgent plist file to add as PkgInfo
  -v, --version		Prints the version of this script, then exits
Description:
  Creates the simplest possible Mac app from a shell script.
  Appify has one required parameter, the script to appify:
    $SCRIPT --script my-app-script.sh
  Note that you cannot rename appified apps. If you want to give your app
  a custom name, use the '--name' option
    $SCRIPT --script my-app-script.sh --name "Sweet"
Copyright:
  Copyright (c) Thomas Aylott <http://subtlegradient.com/>
  Modified by Mathias Bynens <http://mathiasbynens.be/>
  Modified by Andrew Dvorak <http://OhReally.net/>
  Rewritten by Duncan McGreggor <http://github.com/oubiwann/>
EOF
	exit 1
}

function version {
	echo "v${VERSION}"
	exit 1
}

function error {
	echo
	echo "ERROR: $1"
	echo
	usage
}

while :; do
  case $1 in
    -h | --help )        usage;;
    -s | --script )      APPSCRIPT="$2"; shift ;;
    -n | --name )        APPNAME="$2"; shift ;;
    -i | --icons )       APPICONS="$2"; shift ;;
    -d | --document )    APPDOC="$2"; shift ;;
    -p | --persistence ) APPPERSIST="$2"; shift ;;
    -v | --version )     version;;
    -- )                 shift; break ;;
    * )                  break ;;
  esac
  shift
done

if [ -z ${APPSCRIPT+nil} ]; then
	error "the script to appify must be provided!"
fi

if [ ! -f "$APPSCRIPT" ]; then
	error "the can't find the script '$APPSCRIPT'"
fi

if [ -a "$APPNAME.app" ]; then
    rm -rf "$APPNAME.app"
fi

APPDIR="$APPNAME.app/Contents"

mkdir -vp "$APPDIR"/{MacOS,Resources}
cp -v "$APPICONS" "$APPDIR/Resources/icon.icns"
cp -v "$APPDOC" "$APPDIR/Resources/default.config"
cp -v "$APPSCRIPT" "$APPDIR/MacOS/$APPNAME"
cp -v "$APPPERSIST" "$APPDIR/PkgInfo"
chmod +x "$APPDIR/MacOS/$APPNAME"

cat <<EOF > "$APPDIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>CFBundleExecutable</key>
    <string>$APPNAME</string>
    <key>CFBundleGetInfoString</key>
    <string>$APPNAME</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>CFBundleName</key>
    <string>$APPNAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>4242</string>
  </dict>
</plist>
EOF

echo "Application bundle created at '$PWD/$APPNAME.app'\n"

