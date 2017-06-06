#!/bin/bash

readonly DATE=`date +'%Y%m%d'`

echo "** Generate CloudGatewayStorageManagerConfiguration.tex from the XML"
xsltproc -o CloudGatewayStorageManagerConfiguration.tex XmlConfigurationToLatex.xsl ../configurations/CloudGatewayStorageManagerConfiguration.xml
sed -i 's/_/\\_/g' CloudGatewayStorageManagerConfiguration.tex
sed -i 's/#/\\#/g' CloudGatewayStorageManagerConfiguration.tex

rm -f rubber.out
echo "** Run rubber --pdf manual.tex" | tee rubber.out
rubber --pdf manual.tex 2>> rubber.out
cp manual.pdf "CloudGateway_Reference_Manual_${DATE}.pdf"

echo "** Run rubber --pdf --clean manual.tex" | tee -a rubber.out
rubber --pdf --clean manual.tex 2>> rubber.out
echo "** Documentation file: CloudGateway_Reference_Manual_${DATE}.pdf"
