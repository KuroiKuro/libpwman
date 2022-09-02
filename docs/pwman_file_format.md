# PWMan File Format Specification
This document will describe the PWMan file format specification

## Sections
The file can be separated into 2 sections: the header section, and the data section. The header section contains the file metadata, and the data section contains the password entries that are saved to the database

## File Header

The file header contains the following information, in order:
1. File signature. Basically, every `.pwman` file has to start with `7F 70 77 6D 61 6E 2B 2E`.
2. Endianness. With the exception of the file header bytes, which should be in Big Endian (i.e read as is), the file bytes should always be stored in Little Endian, but as way of confirmation, the byte after the file signature will be `00` to indicate that the Endianness is Little Endian. If somehow the data is stored in Big Endian, then the byte should be `01`.
3. Length of checksum. The length of the checksum in the next section.
4. CRC32 checksum. A CRC32 checksum is used instead of a more secure hashing algorithm because the information in the header is not security-critical, so the checksum will serve more as an error check, to ensure that the file was created or copied correctly without data loss.
5. File version. This follows a `major.minor` version format (e.g. `1.2`). The version is stored as 2 bytes, where the first byte is the major version, and the second byte the minor version. As an example, version `1.2` will be represented as `02 01` in Little Endian format.
6. Offset to end of header section. This will allow easy slicing of the header section that should be checked with the CRC32 checksum embedded before.
7. Offset to data. This will represent the offset from the beginning of the file to the data section. This is present to allow applications to be able to skip directly to the data. Can be useful if new header fields are added over time, which older application version do not know how to parse. It might seem redundant since there is already an offset to header section, however including this will allow the option of adding an entire new section in between the header and data sections if required.
8. Length of plaintext string. The length of the plaintext string that will follow in the next section.
9. Plaintext string. This is a plaintext string that will be used by applications to test if a user-supplied password generates the right encryption key that can be used to decrypt the passwords contained in the data section.
10. Length of encrypted string. The length of the encrypted string that will follow in the next section.
11. The encrypted string. The plaintext string that was encrypted with a key derived from the user password. This encrypted string will be created and saved on database creation. If the application is able to decrypt this string and verify that it matches with the plaintext string, then it is confirmed that the user has supplied the right password for the password database.
12. The length of MAC. The length of the MAC of the encrypted string.
13. MAC of encrypted string. The MAC Of the encrypted string to prevent tampering with the value of the encrypted string.
14. End of header section. The end of the header section will be marked with the bytes `1B 1C 20`. The offset to the end of header section will be the offset to the location containing the byte `20`. So that means that the end of header section byte marker should be included in the CRC32 checksum verification.

## File Data

