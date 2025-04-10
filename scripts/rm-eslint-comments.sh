#!/usr/bin/env bash

LIB_DIR="../lib"

##########################################################
fix_paths() {
    local SRC=${BASH_SOURCE[0]}
    local TGT=""
    local SCRIPT_DIR=""
    while [ -L "$SRC" ]; do
        TGT=$(readlink "$SRC")
        if [[ $TGT == /* ]]; then
            SRC=$TGT
        else
            SCRIPT_DIR=$( dirname "$SRC" )
            SRC=$SCRIPT_DIR/$TGT
        fi
    done
    SCRIPT_DIR=$( cd -P "$( dirname "$SRC" )" >/dev/null 2>&1 && pwd )
    absolutize () {
        declare -n ARG_PATH=$1
        local ABS_PATH=""
        if [[ ${ARG_PATH:0:1} == "/" ]]
        then
            ABS_PATH=$ARG_PATH
        else
            ABS_PATH="$SCRIPT_DIR/$ARG_PATH"
        fi
        ARG_PATH=$ABS_PATH
    }

    absolutize LIB_DIR
}
fix_paths
##########################################################

echo "Removing eslint comments..."

if ! [ -d "$LIB_DIR" ]; then
    echo "Library files directory not found: \"$LIB_DIR\""
    exit 1
fi

for file in $(find "${LIB_DIR}" -type f \( -name '*.js' -o -name '*.mjs' \)); do
    # Remove any single-line ESLint comments like:
    # // eslint-disable
    # // eslint-disable-line
    # // eslint-disable-next-line
    # // eslint-enable
    # // eslint <rule>: <value>
    sed -i '/\/\/.*eslint.*/d' "$file"

    # Remove block comments that affect ESLint:
    # /* eslint-disable */
    # /* eslint-enable */
    # /* eslint <rule>: <value> */
    sed -i '/\/\*.*eslint.*\*\//d' "$file"

    # Optionally remove multi-line block comments with eslint configs
    # (start of block)
    sed -i '/\/\*.*eslint.*/{:a;N;/\*\//!ba;d}' "$file"
done

echo "Done"
echo ""
