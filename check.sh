RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
CYAN="\e[36m"

BOLD="\E[1m"
RESET="\e[0m"

verbose=""
volatility=""
dumps_path=""
help=0
while [ "$1" != "" ]; do
  case $1 in
    --volatility   ) volatility=$2
                     shift
                     shift
                     ;;
    -v | --verbose ) verbose="-v "
                     shift
                     ;;
    -d | --dumps   ) dumps_path=$2
                     shift
                     shift
                     ;;
    -h | --help    ) help=1
                     shift
                     ;;
  esac
done

if [[ $help == 0 && ("x$volatility" == "x" || "x$dumps_path" == "x") ]]; then
  echo -e "${RED}ERROR: the volatility path and the dumps paths requires to be specified.${RESET}"
  help=1
fi

if [[ $help == 1 || $help == 2 ]]; then
  echo "Checkpstree volatility plugin utility launcher"
  echo "Launches volatility with the checkpstree plugin on all the memory dumps provided in the dumps folder"
  echo "Options:"
  echo "  --volatility [path]"
  echo "    path to the folder where volatility is installed"
  echo "  -v"
  echo "  -verbose"
  echo "    launch the checkpstree plugin in verbose mode"
  echo "  -d [path]"
  echo "  --dumps [path]"
  echo "    folder containing the Windows XP and 7 image dumps to test"
  echo "  -h"
  echo "  --help"
  echo "    display $0 help"
  echo ""
  echo "Note: the memory dumps in must be named \"<name>.<profile>\" without the (\")"
  echo "  <name> can be whatever you want"
  echo "  <profile> must be one of the profiles supported by volatility and checkpstree"
  echo "    for example Win7SP1x86, WinXPSP2x86, etc."
  if [ $help == 2 ]; then
    exit 1
  fi
  exit 0
fi

for filename in `ls ${dumps_path}`; do
  echo -e "${BOLD}${GREEN}${filename}${RESET}"
  profile="${filename##*.}"
  echo -e "${GREEN}python ${volatility}/vol.py --plugins `pwd`/plugin checkpstree --profile ${profile} ${verbose} -f ${dumps_path}/${filename}${RESET}"
  python ${volatility}/vol.py --plugins `pwd`/plugin checkpstree --profile ${profile} ${verbose} -f ${dumps_path}/${filename} > /tmp/checkpstree.tmp 2>&1
  if [ $? -eq 0 ]; then
    echo -e "${CYAN}"
  else
    echo -e "${RED}"
  fi
  cat /tmp/checkpstree.tmp
  echo -e "${RESET}"
done
