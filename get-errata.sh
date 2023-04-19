#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.sh : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.sh RHSA-2023-0951.html
# 
VERSION="3.0.2"
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
while getopts "anhx" opt; do
  case $opt in
   a) opt_aarch64='True'
       echo "option -a specified"
       ;;
   x) opt_x86_64='True'
       echo "option -x specified"
       ;;
   n) opt_no_download='True'
      echo "option -n specified"
      ;;
   h) echo "Usage bash -x get-errata.sh [options] <errata-webpage.html>"
       echo ""
       echo "Options:"
       echo "-n No Download."
       echo "-a aarch64"       
       exit 0
       ;;
    \?) echo "Invalid option -$OPTARG" >&2;;
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
    product_pattern="^.h2.Red Hat Enterprise Linux.*(ARM)"
    rpm_pattern="src.rpm\|aarch64\|noarch"
    echo "ARM downloading"
    echo  $opt_x86_64
else
    # （その他）x86_64の場合のダウンロード
    product_pattern="^.h2.Red Hat Enterprise Linux.*(x86_64|AUS|(Extended Life Cycle Support)|(Server 7))"
    rpm_pattern="src.rpm\|x86_64\|i686\|noarch"
fi

# デバッグ機能
if [ "$opt_x86_64" = "True" ]; then
    # 強制的にx86_64の場合のダウンロードを実施する。
    echo "forcing x86_64 downloading"
    product_pattern="^.h2.Red Hat Enterprise Linux.*(x86_64|AUS|(Extended Life Cycle Support)|(Server 7))"
    rpm_pattern="src.rpm\|x86_64\|i686\|noarch"
fi

echo $product_pattern
echo $rpm_pattern
#
# rpm-pkgのダウンロードリンクの抽出
#  何故 400行としたか？ 2023yの時点でx86_64カーネルエラッタの取得が htmlテーブル上に 260行程度で記載されており、
# 将来パッケージ数の増加に対応できるようにした。(product B欄は IBMzなので２番目のgrepで除外される。)
egrep -m 1 -A 800 "$product_pattern" $file_name | grep auth_= |gawk '{print $5}'|sort -u|grep "$rpm_pattern" |gawk -F">" '{print $1}'|sed 's/href=//g'|sed 's/\&amp;/\&/g'|gawk -F"[/?]" '{print "curl --output " $11 " " $0}' > $sh_filename    
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
  echo "ダウンロードが失敗したファイルがあります。表示されたチェックサムのファイルを再度ダウンロードしてみてください。"
else
  echo "正常にダウンロードされました"
fi
# ディレクトリを作成しrpm格納する
# ディレクトリ名の取り出し
output_dir="${file_name%.*}"
mkdir -p $output_dir/SRPM
mkdir -p $output_dir/x86_64
mv *.src.rpm $output_dir/SRPM
mv *.rpm $output_dir/x86_64
tree $output_dir/ >${output_dir}-tree.txt



