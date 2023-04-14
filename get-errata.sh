#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.sh : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.sh RHSA-2023-0951.html
# 
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
file_name=$1
# 拡張子を変更しダウンロードスクリプト名とする
sh_filename="${file_name%.*}.sh"
egrep -m 1 -A 400 "^.h2.Red Hat Enterprise Linux.*x86_64" $file_name | grep auth_= |gawk '{print $5}'|sort -u|grep "src.rpm\|x86_64\|noarch"|gawk -F">" '{print $1}'|sed 's/href=//g'|sed 's/\&amp;/\&/g'|gawk -F"[/?]" '{print "curl --output " $11 " " $0}' > $sh_filename
#  何故 400行としたか？ 2023yの時点でx86_64カーネルエラッタの取得が htmlテーブル上に 260行程度で記載されており、
# 将来パッケージ数の増加に対応できるようにした。(product B欄は IBMzなので２番目のgrepで除外される。)
#
# ダウンロードスクリプトの実行
sh $sh_filename
sha256sum *rpm >sha256sum.txt
# ダウンロードしたrpmの数を数えておく27以下だと失敗しているかも。
wc sha256sum.txt
gawk '{print $1}' sha256sum.txt >sha256key
# ダウンロード元のチェックサムを集める。
egrep -m 1 -A 400 "^.h2.Red Hat Enterprise Linux.*x86_64" $file_name | grep -B2 "src.rpm\|x86_64\|noarch" |grep SHA-256:|sort -u|gawk -F"<" '{print $2}'|gawk '{print $3}' >sha256sum.lst  
echo 'checking original'
grep -v -f sha256key sha256sum.lst
result=$(grep -v -f sha256key sha256sum.lst )
if [ -n "$result" ]; then
  echo "ダウンロードが失敗したファイルがあります。表示されたチェックサムのファイルを再度ダウンロードしてみてください。"
else
  echo "正常にダウンロードされました"
fi

