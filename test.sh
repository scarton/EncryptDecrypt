#!/bin/sh

        #echo "java -cp ./bin/lib/bcprov-jdk15on-152.jar:./bin/lib/commons-cli-1.2.jar:./bin/classes com.rsc.encdec.EncryptDecrypt -k $2 -e $1 -i $3 -o $4"
        java -cp ./bin/lib/bcprov-jdk15on-152.jar:./bin/lib/commons-cli-1.2.jar:./bin/classes com.rsc.encdec.EncryptDecrypt -k $2 -e $1 -i $3 -o $4
