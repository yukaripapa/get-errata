#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.sh : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.sh RHSA-2023-0951.html
# 
VERSION="5.99"
#  htmlファイルに含まれるダウンロードリンクを集め
# rpmのダウンロードとチェックサム確認を行う。
# ファイルの内容からダウンロードリンクを集め curlを実行するシェルスクリプトを作成する。
# html内の特定の製品名とアーキテクチャに制限してダウンロードリンクを抽出している。
# これらの制限を外せば、より柔軟に対応できる。
#
#  errata-page.html
# +-------------+
# |Description  |
# |             |
# |Download List|
# |%%%%%%%%%%%  |A
# |%product A%  || この辺りに含まれるURLから
# |%%%%%%%%%%%  ||ダウンロードリンクを抽出する。
# |+---------+  ||
# ||product B|  |V
# |+---------+  |
# |+---------+  |
# ||product C|  |
# |+---------+  |
# ;     ;       ;
#
# オプションの取得
# -a aarch64のダウンロードを行う. デフォルトは x86_64
# -n No Download. ダウンロードスクリプトの実行はせず、その他を実行する。（チェックサムの確認等）
help_txt="
Usage bash -x get-errata.sh [options] errata-webpage.html

version=$VERSION
Options:
  -h help
  -a aarch64
  -d all download
  -n No Download. (just re-generate checksums.)
"

if [ $# -eq 0 ]; then
  echo -e "$help_txt"
  exit 0
fi

while getopts "andhxv" opt; do
  case $opt in
   a) opt_aarch64='True'
      echo "option -a specified"
       ;;
   d) opt_all_download='True'
      echo "option -d specified"
       ;;
   x) opt_x86_64='True'
      echo "option -x specified"
       ;;
   n) opt_no_download='True'
      echo "option -n specified"
       ;;
   v) echo "version $VERSION"
      exit 0
       ;;
   h) echo -e "$help_txt"
      exit 0
       ;;
   \?) echo "Invalid option -$OPTARG" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

file_name=$1


# 拡張子を変更しダウンロードスクリプト名とする
sh_filename="${file_name%.*}.sh"
#
# ダウンロードするアーキテクチャ毎の設定
# デフォルト x86_64（i686も含む）
echo $opt_aarch64
if [ "$opt_aarch64" = "True"  ]; then
    # aarch64の場合のダウンロード
    product_pattern="^.h2.Red Hat Enterprise Linux.*ARM"
    rpm_pattern="src.rpm\|aarch64\|noarch"
    echo "ARM downloading"
    echo  $opt_x86_64
else
    # （その他）x86_64の場合のダウンロード
    product_pattern="^.h2.Red Hat Enterprise Linux.*(AUS|(x86_64.*SAP)|(x86_64 [89])|(x86_64 .*Update Support)|(Extended Life Cycle Support)|(Server 7)|(Real Time 7))"
    rpm_pattern="src.rpm\|x86_64\|i686\|noarch"
fi

# デバッグ機能
if [ "$opt_x86_64" = "True" ]; then
    # 強制的にx86_64の場合のダウンロードを実施する。
    echo "forcing x86_64 downloading"
    product_pattern="^.h2.Red Hat Enterprise Linux.*(AUS|(x86_64.*SAP)|(x86_64 [89])|(x86_64 .*Update Support)|(Extended Life Cycle Support)|(Server 7))"
    rpm_pattern="src.rpm\|x86_64\|i686\|noarch"
fi

#
# rpm-pkgのダウンロードリンクの抽出
#  何故 800行としたか？ 2023yの時点でx86_64カーネルエラッタの取得が htmlテーブル上に 260行程度で記載されており、
# 将来パッケージ数の増加に対応できるようにした。(product B欄は IBMzなので２番目のgrepで除外される。)
search_depth=800
if [ "$opt_all_download" = "True"  ]; then
# 特別パッケージ量が多い場合はダウンロードリンクを多めにサーチする
   search_depth=30000
fi
egrep -m 2 -A $search_depth "$product_pattern" $file_name | grep auth_= |gawk '{print $5}'|sort -u|grep "$rpm_pattern" |gawk -F">" '{print $1}'|sed 's/href=//g'|sed 's/\&amp;/\&/g'|gawk -F"[/?]" '{print "echo " NR ":" $11 "; curl --output " $11 " " $0}' > $sh_filename    
# ダウンロードスクリプトの実行
echo $opt_no_download
if [ -z $opt_no_download  ]; then
    sh $sh_filename
else
    # -n オプションの場合はダウンロードせずスキップする。
    echo "No Downloading specified."
fi

sha256sum *rpm >sha256sum.txt
# ダウンロードしたrpmの数を数えておく27以下だと失敗しているかも。
wc sha256sum.txt
gawk '{print $1}' sha256sum.txt >sha256key
# ダウンロード元のチェックサムを集める。
egrep -m 1 -A 400 "$product_pattern" $file_name | grep -B2 "$rpm_pattern" |grep SHA-256:|sort -u|gawk -F"<" '{print $2}'|gawk '{print $3}' >sha256sum.lst  
echo 'checking original'
grep -v -f sha256key sha256sum.lst
result=$(grep -v -f sha256key sha256sum.lst )
if [ -n "$result" ]; then
  echo "some downloads are broken. check sha256sum belows..."
else
  echo "Downloading is finished!"
fi
# ディレクトリを作成しrpm格納する
# ディレクトリ名の取り出し
output_dir="${file_name%.*}"
#
# rhel7かどうか判定
#
is_el7="False"
if ls *el7*rpm >/dev/null 2>&1; then 
    is_el7="True"
    echo "el7 detected"
fi
#
# rhel8かどうか判定
#
is_el8="False"
if ls *el8*rpm >/dev/null 2>&1; then 
    is_el8="True"
    echo "el8 detected"
fi
#
# rhel9かどうか判定
#
is_el9="False"
if ls *el9*rpm >/dev/null 2>&1; then 
    is_el9="True"
    echo "el9 detected"
fi

# ディレクトリを作成しrpm格納する
# ディレクトリ名の取り出し
output_dir="${file_name%.*}"
# ソースコードの格納
mkdir -p $output_dir/SRPM
mv *.src.rpm $output_dir/SRPM
if [ "$opt_aarch64" = "True"  ]; then
    # ARMの場合は aarch64へ格納
    mkdir -p $output_dir/aarch64
    mv *.rpm $output_dir/aarch64
elif ls kernel*.i686.rpm >/dev/null 2>&1; then 
    # x86_64(i686含む)の場合はx86_64/i686へ分けて格納    
    echo "i686.rpm existing"
    mkdir -p $output_dir/x86_64
    mkdir -p $output_dir/i686
    mv *i686.rpm $output_dir/i686
    cp *noarch.rpm $output_dir/i686
    mv *.rpm $output_dir/x86_64
    # 以下の6つのpkgを x86_64フォルダーにコピーする
    cp $output_dir/i686/kernel-debug-debuginfo-*.i686.rpm $output_dir/x86_64
    cp $output_dir/i686/kernel-debug-devel-*.el6.i686.rpm $output_dir/x86_64
    cp $output_dir/i686/kernel-debuginfo-*.i686.rpm $output_dir/x86_64
    cp $output_dir/i686/kernel-debuginfo-common-*.el6.i686.rpm $output_dir/x86_64
    cp $output_dir/i686/perf-debuginfo-*.i686.rpm $output_dir/x86_64
    cp $output_dir/i686/python-perf-debuginfo-*.i686.rpm $output_dir/x86_64
else
    # それ以外のx86_64の場合はx86_64へまとめて格納    
    mkdir -p $output_dir/x86_64
    mv *.rpm $output_dir/x86_64
fi

#
# ダウンロード不要パッケージを削除する。
#
# !el7 kernel-tools-libs-devel
if [ "$is_el7" = "False"  ]; then
  du -a $output_dir/ | grep -v el7 | grep kernel-tools-libs-devel | gawk '{print "rm " $2}' | sh
fi
#
# el9 kernel-cross-headers
if [ "$is_el9" = "True"  ]; then
  du -a $output_dir/ | grep el9 | grep kernel-cross-headers | gawk '{print "rm " $2}' | sh
  du -a $output_dir/ | grep el9 | grep internal-5 | gawk '{print "rm " $2}' | sh
  du -a $output_dir/ | grep el9 | grep modules-partner | gawk '{print "rm " $2}' | sh      
fi
#
# el8/el9 glibc
if [ "$is_el8" = "True" -o "$is_el9" = "True"  ]; then
  du -a $output_dir/ | grep glibc-benchtests-2 | gawk '{print "rm " $2}' | sh
  du -a $output_dir/ | grep glibc-nss-devel-2 | gawk '{print "rm " $2}' | sh
  du -a $output_dir/ | grep glibc-static-2 | gawk '{print "rm " $2}' | sh
  du -a $output_dir/ | grep nss_hesiod-2 | gawk '{print "rm " $2}' | sh
  # remove more pkg in el8
  du -a $output_dir/ | grep el8 | grep internal-4 | gawk '{print "rm " $2}' | sh
  # remove more pkg in el9
  du -a $output_dir/ | grep el9 | grep nss_db-2 | gawk '{print "rm " $2}' | sh


fi

# tree/checksumを取得する。
LANG=C tree $output_dir/ >${output_dir}-tree.txt
md5sum $output_dir/*/*.rpm >${output_dir}-md5sum.txt
sha256sum $output_dir/*/*.rpm >${output_dir}-sha256sum.txt
# フォルダーへコピーする
cp ${output_dir}-tree.txt ${output_dir}-md5sum.txt ${output_dir}-sha256sum.txt ${output_dir}



