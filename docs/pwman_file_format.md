# PWMan File Format Specification
This document will describe the PWMan file format specification

# File Version
The version of the file format is currently at `0.1`. This is still **UNSTABLE**, and after it is stable the version will be upgraded to `1.0`.

## Sections
The file can be separated into 2 sections: the header section, and the data section. The header section contains the file metadata, and the data section contains the password entries that are saved to the database

## File Header

The file header contains the following information, in order:
1. File signature. Basically, every `.pwman` file has to start with `7F 70 77 6D 61 6E 2B 2E`.

2. Endianness. With the exception of the file header bytes, which should be in Big Endian (i.e read as is), the file bytes should always be stored in Little Endian, but as way of confirmation, the byte after the file signature will be `00` to indicate that the Endianness is Little Endian. If somehow the data is stored in Big Endian, then the byte should be `01`.

3. Length of checksum. The length of the checksum in the next section.

4. CRC32 checksum. A CRC32 checksum is used instead of a more secure hashing algorithm because the information in the header is not security-critical, so the checksum will serve more as an error check, to ensure that the file was created or copied correctly without data loss. This checksum will be calculated from the following information (file version) to the end of the header section

5. File version. This follows a `major.minor` version format (e.g. `1.2`). The version is stored as 2 bytes, where the first byte is the major version, and the second byte the minor version. As an example, version `1.2` will be represented as `02 01` in Little Endian format.

6. Offset to end of header section (8 bytes). This will allow easy slicing of the header section that should be checked with the CRC32 checksum embedded before.

7. Offset to data (8 bytes). This will represent the offset from the beginning of the file to the data section. This is present to allow applications to be able to skip directly to the data. Can be useful if new header fields are added over time, which older application version do not know how to parse. It might seem redundant since there is already an offset to header section, however including this will allow the option of adding an entire new section in between the header and data sections if required.

8. Length of plaintext string. The length of the plaintext string that will follow in the next section.

9. Plaintext string. This is a plaintext string that will be used by applications to test if a user-supplied password generates the right encryption key that can be used to decrypt the passwords contained in the data section.

10. Length of encrypted string. The length of the encrypted string that will follow in the next section.

11. The encrypted string. The plaintext string that was encrypted with a key derived from the user password. This encrypted string will be created and saved on database creation. If the application is able to decrypt this string and verify that it matches with the plaintext string, then it is confirmed that the user has supplied the right password for the password database.

12. The length of MAC. The length of the MAC of the encrypted string.

13. MAC of encrypted string. The MAC Of the encrypted string to prevent tampering with the value of the encrypted string.

14. End of header section. The end of the header section will be marked with the bytes `1B 1C 20`. The offset to the end of header section will be the offset to the location containing the byte `20`. So that means that the end of header section byte marker should be included in the CRC32 checksum verification.

|                Name                 |Number of bytes|          Value          |
|-------------------------------------|---------------|-------------------------|
|File signature                       |8              |`7F 70 77 6D 61 6E 2B 2E`|
|Endianness                           |1              |`00` or `01`             |
|Length of checksum                   |2              |Variable                 |
|CRC32 checksum                       |4              |Variable                 |
|File version                         |2              |Variable                 |
|Offset to end of header section      |8              |Variable                 |
|Offset to data                       |8              |Variable                 |
|Length of plaintext string           |2              |Variable                 |
|Plaintext string                     |Variable       |Variable                 |
|Length of encrypted string           |2              |Variable                 |
|Encrypted string                     |Variable       |Variable                 |
|The length of MAC                    |2              |Variable                 |
|MAC of encrypted string              |Variable       |Variable                 |
|End of header section                |3              |`1B 1C 20`               |

## File Data

The file data section contains the various password entries that are saved in the password database. The entries are saved in a linked list style, where each entry will include the offset from the beginning of the file to the next entry.

### Password Entry Metadata
Each password entry will include the following metadata information at the start of the entry:

1. Password entry start marker. Each password entry will have the bytes `E0 9D 19 14` to indicate that this is the start of a password entry.

2. The offset to the next entry (8 bytes). This will allow the application to be able to follow the list to the next entry without needing to parse the rest of the current entry.

3. SHA256 Checksum of the entry. The checksum is calculated from the ID of the entry to all of the data in the entry data section.

4. The ID of the entry. The ID of the entry is a UUID4 that is stored as bytes. This will allow unique identification of the entry when it needs to be updated in the file.

|             Name           |Number of bytes|    Value    |
|----------------------------|---------------|-------------|
|Password entry start marker |4              |`E0 9D 19 14`|
|Offset to the next entry    |8              |Variable     |
|SHA256 Checksum of the entry|32             |Variable     |
|Entry ID (UUID4)            |16             |Variable     |

### Password Entry Data

The rest of the entry will contain the actual password and related information of the entry, such as the title, URLs etc. All of these information will be encrypted as well to prevent snooping.

1. The length of the encrypted title (8 bytes).

2. The encrypted title.

3. The length of the encrypted password (8 bytes).

4. The encrypted password.

5. The length of the encrypted username (8 bytes).

6. The encrypted username

7. The length of the encrypted notes (8 bytes).

8. The encrypted notes.

9. The number of URLs (4 bytes). The data structure of 9 and 10 will be repeated for each of the URLs that are saved. If the number is 0, then the application should skip the parsing of URLs.

10. The length of the encrypted URL (8 bytes).

11. The encrypted URL.

12. The number of custom fields (4 bytes). The data structure of 13, 14, 15 and 16 will be repeated for each custom field. If the number is 0, then the application should skip the parsing of custom fields.

13. The length of the encrypted name of the custom field (8 bytes).

14. The encrypted name of the custom field.

15. The length of the encrypted value of the custom field (8 bytes).

16. The encrypted value of the custom field.

|                Name               |Number of bytes|    Value    |
|-----------------------------------|---------------|-------------|
|Encrypted title length             |8              |Variable     |
|Encrypted title                    |Variable       |Variable     |
|Encrypted password length          |8              |Variable     |
|Encrypted password                 |Variable       |Variable     |
|Encrypted username length          |8              |Variable     |
|Encrypted username                 |Variable       |Variable     |
|Encrypted notes length             |8              |Variable     |
|Encrypted notes                    |Variable       |Variable     |
|The number of URLs                 |4              |Variable     |
|Encrypted URL length               |8              |Variable     |
|Encrypted URL                      |Variable       |Variable     |
|The number of Custom Fields        |4              |Variable     |
|Encrypted Custom Field Name length |8              |Variable     |
|Encrypted Custom Field Name        |Variable       |Variable     |
|Encrypted Custom Field Value length|8              |Variable     |
|Encrypted Custom Field Value       |Variable       |Variable     |

### End Entry

At the end of each password entry, the bytes `10 1A` will be included. 

|              Name             |Number of bytes| Value |
|-------------------------------|---------------|-------|
|Password Entry End             |2              |`10 1A`|