#!/usr/bin/env python


# Original version by eric@rosenquist.com, Nov 2017
#
# Quick & dirty utility to read a CSV file containing X.509 certificate
# data in some columns, then parse the certificates and replace those
# columns with the parsed certificate data.
#
# Given a PCAP file, you can generate a CSV file of TLS certificates using
# a command-line like this:
#
# tshark -n -r testbed-13jun.pcap -2 -R 'ssl.handshake.certificates' -E separator=, -E header=y -T fields -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssl.handshake.certificate
#
# If there are multiple certificates (a server often returns the full certificate chain) you'll get one
# column per certificate, so make sure the "-e ssl.handshake.certificate" field is at the end of the list
#
# You can then edit the CSV file and provide friendlier column names


'''
BSD 3-Clause License

Copyright (c) 2017, Eric Rosenquist
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import argparse
import csv
import OpenSSL
import sys

def main():
    parser = argparse.ArgumentParser(description='Decodes certificate data within a CSV file.')
    parser.add_argument('inputFile', type=file, nargs='?', help='the input CSV file')
    parser.add_argument('outputFile', type=argparse.FileType('w'), nargs='?', help='the output CSV file')
    parser.add_argument('--certColumns', type=str, metavar='colName colName ...', nargs='*', help='column names containing certificate data.')
    
    args = parser.parse_args()

    certFields = ['digest',
                  'issuer', 'issuer_C', 'issuer_ST', 'issuer_L', 'issuer_O', 'issuer_OU', 'issuer_CN',
                  'subject', 'subject_C', 'subject_ST', 'subject_L', 'subject_O', 'subject_OU', 'subject_CN',
                  'size']

    csvReader = csv.DictReader(args.inputFile)
    csvWriter = None

    for row in csvReader:
        if csvWriter is None:
            fieldNames = csvReader.fieldnames
            for col in args.certColumns:
                fieldNames = [field for field in fieldNames if field != col]
                for certField in certFields:
                    fieldNames.append(col + '_' + certField)
            csvWriter = csv.DictWriter(args.outputFile, fieldNames)
            csvWriter.writeheader()

        outputRow = row.copy()

        for cerCol in args.certColumns:
            binData = None
            outputRow.pop(cerCol)
            if row.get(cerCol, None) is not None:
                try:
                    binData = bytearray.fromhex(row[cerCol].replace(':', ' '))
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, str(binData))
                except OpenSSL.crypto.Error as ex:
                    print >> sys.stderr, "Line {0}: unable to decode certificate data in column {1}".format(csvReader.line_num, cerCol)
                if cert is not None:
                    issuer = cert.get_issuer()
                    subject = cert.get_subject()
                    outputRow[cerCol + '_digest'] = cert.digest('sha1')
                    outputRow[cerCol + '_issuer'] = str(issuer).replace("<X509Name object '", "")[:-2]
                    outputRow[cerCol + '_issuer_C'] = issuer.C
                    outputRow[cerCol + '_issuer_ST'] = issuer.ST
                    outputRow[cerCol + '_issuer_L'] = issuer.L
                    outputRow[cerCol + '_issuer_O'] = issuer.O
                    outputRow[cerCol + '_issuer_OU'] = issuer.OU
                    outputRow[cerCol + '_issuer_CN'] = issuer.CN
                    outputRow[cerCol + '_size'] = len(binData)
                    outputRow[cerCol + '_subject'] = str(subject).replace("<X509Name object '", "")[:-2]
                    outputRow[cerCol + '_subject_C'] = subject.C
                    outputRow[cerCol + '_subject_ST'] = subject.ST
                    outputRow[cerCol + '_subject_L'] = subject.L
                    outputRow[cerCol + '_subject_O'] = subject.O
                    outputRow[cerCol + '_subject_OU'] = subject.OU
                    outputRow[cerCol + '_subject_CN'] = subject.CN

        csvWriter.writerow(outputRow)


if __name__ == '__main__':
    main()
