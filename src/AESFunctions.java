import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Scanner;

public class AESFunctions {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static final int Nb = 4;

    private static final int Nk = 4;

    private static final int NumRounds = 10;

    private static final int Rcon[] = {0x01000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000, 0x6c000000};

    private static final byte[][] Gmul2 = {
            {(byte) 0x00, (byte) 0x02, (byte) 0x04, (byte) 0x06, (byte) 0x08, (byte) 0x0a, (byte) 0x0c, (byte) 0x0e, (byte) 0x10, (byte) 0x12, (byte) 0x14, (byte) 0x16, (byte) 0x18, (byte) 0x1a, (byte) 0x1c, (byte) 0x1e},
            {(byte) 0x20, (byte) 0x22, (byte) 0x24, (byte) 0x26, (byte) 0x28, (byte) 0x2a, (byte) 0x2c, (byte) 0x2e, (byte) 0x30, (byte) 0x32, (byte) 0x34, (byte) 0x36, (byte) 0x38, (byte) 0x3a, (byte) 0x3c, (byte) 0x3e},
            {(byte) 0x40, (byte) 0x42, (byte) 0x44, (byte) 0x46, (byte) 0x48, (byte) 0x4a, (byte) 0x4c, (byte) 0x4e, (byte) 0x50, (byte) 0x52, (byte) 0x54, (byte) 0x56, (byte) 0x58, (byte) 0x5a, (byte) 0x5c, (byte) 0x5e},
            {(byte) 0x60, (byte) 0x62, (byte) 0x64, (byte) 0x66, (byte) 0x68, (byte) 0x6a, (byte) 0x6c, (byte) 0x6e, (byte) 0x70, (byte) 0x72, (byte) 0x74, (byte) 0x76, (byte) 0x78, (byte) 0x7a, (byte) 0x7c, (byte) 0x7e},
            {(byte) 0x80, (byte) 0x82, (byte) 0x84, (byte) 0x86, (byte) 0x88, (byte) 0x8a, (byte) 0x8c, (byte) 0x8e, (byte) 0x90, (byte) 0x92, (byte) 0x94, (byte) 0x96, (byte) 0x98, (byte) 0x9a, (byte) 0x9c, (byte) 0x9e},
            {(byte) 0xa0, (byte) 0xa2, (byte) 0xa4, (byte) 0xa6, (byte) 0xa8, (byte) 0xaa, (byte) 0xac, (byte) 0xae, (byte) 0xb0, (byte) 0xb2, (byte) 0xb4, (byte) 0xb6, (byte) 0xb8, (byte) 0xba, (byte) 0xbc, (byte) 0xbe},
            {(byte) 0xc0, (byte) 0xc2, (byte) 0xc4, (byte) 0xc6, (byte) 0xc8, (byte) 0xca, (byte) 0xcc, (byte) 0xce, (byte) 0xd0, (byte) 0xd2, (byte) 0xd4, (byte) 0xd6, (byte) 0xd8, (byte) 0xda, (byte) 0xdc, (byte) 0xde},
            {(byte) 0xe0, (byte) 0xe2, (byte) 0xe4, (byte) 0xe6, (byte) 0xe8, (byte) 0xea, (byte) 0xec, (byte) 0xee, (byte) 0xf0, (byte) 0xf2, (byte) 0xf4, (byte) 0xf6, (byte) 0xf8, (byte) 0xfa, (byte) 0xfc, (byte) 0xfe},
            {(byte) 0x1b, (byte) 0x19, (byte) 0x1f, (byte) 0x1d, (byte) 0x13, (byte) 0x11, (byte) 0x17, (byte) 0x15, (byte) 0x0b, (byte) 0x09, (byte) 0x0f, (byte) 0x0d, (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x05},
            {(byte) 0x3b, (byte) 0x39, (byte) 0x3f, (byte) 0x3d, (byte) 0x33, (byte) 0x31, (byte) 0x37, (byte) 0x35, (byte) 0x2b, (byte) 0x29, (byte) 0x2f, (byte) 0x2d, (byte) 0x23, (byte) 0x21, (byte) 0x27, (byte) 0x25},
            {(byte) 0x5b, (byte) 0x59, (byte) 0x5f, (byte) 0x5d, (byte) 0x53, (byte) 0x51, (byte) 0x57, (byte) 0x55, (byte) 0x4b, (byte) 0x49, (byte) 0x4f, (byte) 0x4d, (byte) 0x43, (byte) 0x41, (byte) 0x47, (byte) 0x45},
            {(byte) 0x7b, (byte) 0x79, (byte) 0x7f, (byte) 0x7d, (byte) 0x73, (byte) 0x71, (byte) 0x77, (byte) 0x75, (byte) 0x6b, (byte) 0x69, (byte) 0x6f, (byte) 0x6d, (byte) 0x63, (byte) 0x61, (byte) 0x67, (byte) 0x65},
            {(byte) 0x9b, (byte) 0x99, (byte) 0x9f, (byte) 0x9d, (byte) 0x93, (byte) 0x91, (byte) 0x97, (byte) 0x95, (byte) 0x8b, (byte) 0x89, (byte) 0x8f, (byte) 0x8d, (byte) 0x83, (byte) 0x81, (byte) 0x87, (byte) 0x85},
            {(byte) 0xbb, (byte) 0xb9, (byte) 0xbf, (byte) 0xbd, (byte) 0xb3, (byte) 0xb1, (byte) 0xb7, (byte) 0xb5, (byte) 0xab, (byte) 0xa9, (byte) 0xaf, (byte) 0xad, (byte) 0xa3, (byte) 0xa1, (byte) 0xa7, (byte) 0xa5},
            {(byte) 0xdb, (byte) 0xd9, (byte) 0xdf, (byte) 0xdd, (byte) 0xd3, (byte) 0xd1, (byte) 0xd7, (byte) 0xd5, (byte) 0xcb, (byte) 0xc9, (byte) 0xcf, (byte) 0xcd, (byte) 0xc3, (byte) 0xc1, (byte) 0xc7, (byte) 0xc5},
            {(byte) 0xfb, (byte) 0xf9, (byte) 0xff, (byte) 0xfd, (byte) 0xf3, (byte) 0xf1, (byte) 0xf7, (byte) 0xf5, (byte) 0xeb, (byte) 0xe9, (byte) 0xef, (byte) 0xed, (byte) 0xe3, (byte) 0xe1, (byte) 0xe7, (byte) 0xe5}};

    private static final byte[][] Gmul3 = {
            {(byte) 0x00, (byte) 0x03, (byte) 0x06, (byte) 0x05, (byte) 0x0c, (byte) 0x0f, (byte) 0x0a, (byte) 0x09, (byte) 0x18, (byte) 0x1b, (byte) 0x1e, (byte) 0x1d, (byte) 0x14, (byte) 0x17, (byte) 0x12, (byte) 0x11},
            {(byte) 0x30, (byte) 0x33, (byte) 0x36, (byte) 0x35, (byte) 0x3c, (byte) 0x3f, (byte) 0x3a, (byte) 0x39, (byte) 0x28, (byte) 0x2b, (byte) 0x2e, (byte) 0x2d, (byte) 0x24, (byte) 0x27, (byte) 0x22, (byte) 0x21},
            {(byte) 0x60, (byte) 0x63, (byte) 0x66, (byte) 0x65, (byte) 0x6c, (byte) 0x6f, (byte) 0x6a, (byte) 0x69, (byte) 0x78, (byte) 0x7b, (byte) 0x7e, (byte) 0x7d, (byte) 0x74, (byte) 0x77, (byte) 0x72, (byte) 0x71},
            {(byte) 0x50, (byte) 0x53, (byte) 0x56, (byte) 0x55, (byte) 0x5c, (byte) 0x5f, (byte) 0x5a, (byte) 0x59, (byte) 0x48, (byte) 0x4b, (byte) 0x4e, (byte) 0x4d, (byte) 0x44, (byte) 0x47, (byte) 0x42, (byte) 0x41},
            {(byte) 0xc0, (byte) 0xc3, (byte) 0xc6, (byte) 0xc5, (byte) 0xcc, (byte) 0xcf, (byte) 0xca, (byte) 0xc9, (byte) 0xd8, (byte) 0xdb, (byte) 0xde, (byte) 0xdd, (byte) 0xd4, (byte) 0xd7, (byte) 0xd2, (byte) 0xd1},
            {(byte) 0xf0, (byte) 0xf3, (byte) 0xf6, (byte) 0xf5, (byte) 0xfc, (byte) 0xff, (byte) 0xfa, (byte) 0xf9, (byte) 0xe8, (byte) 0xeb, (byte) 0xee, (byte) 0xed, (byte) 0xe4, (byte) 0xe7, (byte) 0xe2, (byte) 0xe1},
            {(byte) 0xa0, (byte) 0xa3, (byte) 0xa6, (byte) 0xa5, (byte) 0xac, (byte) 0xaf, (byte) 0xaa, (byte) 0xa9, (byte) 0xb8, (byte) 0xbb, (byte) 0xbe, (byte) 0xbd, (byte) 0xb4, (byte) 0xb7, (byte) 0xb2, (byte) 0xb1},
            {(byte) 0x90, (byte) 0x93, (byte) 0x96, (byte) 0x95, (byte) 0x9c, (byte) 0x9f, (byte) 0x9a, (byte) 0x99, (byte) 0x88, (byte) 0x8b, (byte) 0x8e, (byte) 0x8d, (byte) 0x84, (byte) 0x87, (byte) 0x82, (byte) 0x81},
            {(byte) 0x9b, (byte) 0x98, (byte) 0x9d, (byte) 0x9e, (byte) 0x97, (byte) 0x94, (byte) 0x91, (byte) 0x92, (byte) 0x83, (byte) 0x80, (byte) 0x85, (byte) 0x86, (byte) 0x8f, (byte) 0x8c, (byte) 0x89, (byte) 0x8a},
            {(byte) 0xab, (byte) 0xa8, (byte) 0xad, (byte) 0xae, (byte) 0xa7, (byte) 0xa4, (byte) 0xa1, (byte) 0xa2, (byte) 0xb3, (byte) 0xb0, (byte) 0xb5, (byte) 0xb6, (byte) 0xbf, (byte) 0xbc, (byte) 0xb9, (byte) 0xba},
            {(byte) 0xfb, (byte) 0xf8, (byte) 0xfd, (byte) 0xfe, (byte) 0xf7, (byte) 0xf4, (byte) 0xf1, (byte) 0xf2, (byte) 0xe3, (byte) 0xe0, (byte) 0xe5, (byte) 0xe6, (byte) 0xef, (byte) 0xec, (byte) 0xe9, (byte) 0xea},
            {(byte) 0xcb, (byte) 0xc8, (byte) 0xcd, (byte) 0xce, (byte) 0xc7, (byte) 0xc4, (byte) 0xc1, (byte) 0xc2, (byte) 0xd3, (byte) 0xd0, (byte) 0xd5, (byte) 0xd6, (byte) 0xdf, (byte) 0xdc, (byte) 0xd9, (byte) 0xda},
            {(byte) 0x5b, (byte) 0x58, (byte) 0x5d, (byte) 0x5e, (byte) 0x57, (byte) 0x54, (byte) 0x51, (byte) 0x52, (byte) 0x43, (byte) 0x40, (byte) 0x45, (byte) 0x46, (byte) 0x4f, (byte) 0x4c, (byte) 0x49, (byte) 0x4a},
            {(byte) 0x6b, (byte) 0x68, (byte) 0x6d, (byte) 0x6e, (byte) 0x67, (byte) 0x64, (byte) 0x61, (byte) 0x62, (byte) 0x73, (byte) 0x70, (byte) 0x75, (byte) 0x76, (byte) 0x7f, (byte) 0x7c, (byte) 0x79, (byte) 0x7a},
            {(byte) 0x3b, (byte) 0x38, (byte) 0x3d, (byte) 0x3e, (byte) 0x37, (byte) 0x34, (byte) 0x31, (byte) 0x32, (byte) 0x23, (byte) 0x20, (byte) 0x25, (byte) 0x26, (byte) 0x2f, (byte) 0x2c, (byte) 0x29, (byte) 0x2a},
            {(byte) 0x0b, (byte) 0x08, (byte) 0x0d, (byte) 0x0e, (byte) 0x07, (byte) 0x04, (byte) 0x01, (byte) 0x02, (byte) 0x13, (byte) 0x10, (byte) 0x15, (byte) 0x16, (byte) 0x1f, (byte) 0x1c, (byte) 0x19, (byte) 0x1a}};

    private static final byte[][] Gmul9 = {
            {(byte) 0x00, (byte) 0x09, (byte) 0x12, (byte) 0x1b, (byte) 0x24, (byte) 0x2d, (byte) 0x36, (byte) 0x3f, (byte) 0x48, (byte) 0x41, (byte) 0x5a, (byte) 0x53, (byte) 0x6c, (byte) 0x65, (byte) 0x7e, (byte) 0x77},
            {(byte) 0x90, (byte) 0x99, (byte) 0x82, (byte) 0x8b, (byte) 0xb4, (byte) 0xbd, (byte) 0xa6, (byte) 0xaf, (byte) 0xd8, (byte) 0xd1, (byte) 0xca, (byte) 0xc3, (byte) 0xfc, (byte) 0xf5, (byte) 0xee, (byte) 0xe7},
            {(byte) 0x3b, (byte) 0x32, (byte) 0x29, (byte) 0x20, (byte) 0x1f, (byte) 0x16, (byte) 0x0d, (byte) 0x04, (byte) 0x73, (byte) 0x7a, (byte) 0x61, (byte) 0x68, (byte) 0x57, (byte) 0x5e, (byte) 0x45, (byte) 0x4c},
            {(byte) 0xab, (byte) 0xa2, (byte) 0xb9, (byte) 0xb0, (byte) 0x8f, (byte) 0x86, (byte) 0x9d, (byte) 0x94, (byte) 0xe3, (byte) 0xea, (byte) 0xf1, (byte) 0xf8, (byte) 0xc7, (byte) 0xce, (byte) 0xd5, (byte) 0xdc},
            {(byte) 0x76, (byte) 0x7f, (byte) 0x64, (byte) 0x6d, (byte) 0x52, (byte) 0x5b, (byte) 0x40, (byte) 0x49, (byte) 0x3e, (byte) 0x37, (byte) 0x2c, (byte) 0x25, (byte) 0x1a, (byte) 0x13, (byte) 0x08, (byte) 0x01},
            {(byte) 0xe6, (byte) 0xef, (byte) 0xf4, (byte) 0xfd, (byte) 0xc2, (byte) 0xcb, (byte) 0xd0, (byte) 0xd9, (byte) 0xae, (byte) 0xa7, (byte) 0xbc, (byte) 0xb5, (byte) 0x8a, (byte) 0x83, (byte) 0x98, (byte) 0x91},
            {(byte) 0x4d, (byte) 0x44, (byte) 0x5f, (byte) 0x56, (byte) 0x69, (byte) 0x60, (byte) 0x7b, (byte) 0x72, (byte) 0x05, (byte) 0x0c, (byte) 0x17, (byte) 0x1e, (byte) 0x21, (byte) 0x28, (byte) 0x33, (byte) 0x3a},
            {(byte) 0xdd, (byte) 0xd4, (byte) 0xcf, (byte) 0xc6, (byte) 0xf9, (byte) 0xf0, (byte) 0xeb, (byte) 0xe2, (byte) 0x95, (byte) 0x9c, (byte) 0x87, (byte) 0x8e, (byte) 0xb1, (byte) 0xb8, (byte) 0xa3, (byte) 0xaa},
            {(byte) 0xec, (byte) 0xe5, (byte) 0xfe, (byte) 0xf7, (byte) 0xc8, (byte) 0xc1, (byte) 0xda, (byte) 0xd3, (byte) 0xa4, (byte) 0xad, (byte) 0xb6, (byte) 0xbf, (byte) 0x80, (byte) 0x89, (byte) 0x92, (byte) 0x9b},
            {(byte) 0x7c, (byte) 0x75, (byte) 0x6e, (byte) 0x67, (byte) 0x58, (byte) 0x51, (byte) 0x4a, (byte) 0x43, (byte) 0x34, (byte) 0x3d, (byte) 0x26, (byte) 0x2f, (byte) 0x10, (byte) 0x19, (byte) 0x02, (byte) 0x0b},
            {(byte) 0xd7, (byte) 0xde, (byte) 0xc5, (byte) 0xcc, (byte) 0xf3, (byte) 0xfa, (byte) 0xe1, (byte) 0xe8, (byte) 0x9f, (byte) 0x96, (byte) 0x8d, (byte) 0x84, (byte) 0xbb, (byte) 0xb2, (byte) 0xa9, (byte) 0xa0},
            {(byte) 0x47, (byte) 0x4e, (byte) 0x55, (byte) 0x5c, (byte) 0x63, (byte) 0x6a, (byte) 0x71, (byte) 0x78, (byte) 0x0f, (byte) 0x06, (byte) 0x1d, (byte) 0x14, (byte) 0x2b, (byte) 0x22, (byte) 0x39, (byte) 0x30},
            {(byte) 0x9a, (byte) 0x93, (byte) 0x88, (byte) 0x81, (byte) 0xbe, (byte) 0xb7, (byte) 0xac, (byte) 0xa5, (byte) 0xd2, (byte) 0xdb, (byte) 0xc0, (byte) 0xc9, (byte) 0xf6, (byte) 0xff, (byte) 0xe4, (byte) 0xed},
            {(byte) 0x0a, (byte) 0x03, (byte) 0x18, (byte) 0x11, (byte) 0x2e, (byte) 0x27, (byte) 0x3c, (byte) 0x35, (byte) 0x42, (byte) 0x4b, (byte) 0x50, (byte) 0x59, (byte) 0x66, (byte) 0x6f, (byte) 0x74, (byte) 0x7d},
            {(byte) 0xa1, (byte) 0xa8, (byte) 0xb3, (byte) 0xba, (byte) 0x85, (byte) 0x8c, (byte) 0x97, (byte) 0x9e, (byte) 0xe9, (byte) 0xe0, (byte) 0xfb, (byte) 0xf2, (byte) 0xcd, (byte) 0xc4, (byte) 0xdf, (byte) 0xd6},
            {(byte) 0x31, (byte) 0x38, (byte) 0x23, (byte) 0x2a, (byte) 0x15, (byte) 0x1c, (byte) 0x07, (byte) 0x0e, (byte) 0x79, (byte) 0x70, (byte) 0x6b, (byte) 0x62, (byte) 0x5d, (byte) 0x54, (byte) 0x4f, (byte) 0x46}};

    private static final byte[][] Gmul11 = {
            {(byte) 0x00, (byte) 0x0b, (byte) 0x16, (byte) 0x1d, (byte) 0x2c, (byte) 0x27, (byte) 0x3a, (byte) 0x31, (byte) 0x58, (byte) 0x53, (byte) 0x4e, (byte) 0x45, (byte) 0x74, (byte) 0x7f, (byte) 0x62, (byte) 0x69},
            {(byte) 0xb0, (byte) 0xbb, (byte) 0xa6, (byte) 0xad, (byte) 0x9c, (byte) 0x97, (byte) 0x8a, (byte) 0x81, (byte) 0xe8, (byte) 0xe3, (byte) 0xfe, (byte) 0xf5, (byte) 0xc4, (byte) 0xcf, (byte) 0xd2, (byte) 0xd9},
            {(byte) 0x7b, (byte) 0x70, (byte) 0x6d, (byte) 0x66, (byte) 0x57, (byte) 0x5c, (byte) 0x41, (byte) 0x4a, (byte) 0x23, (byte) 0x28, (byte) 0x35, (byte) 0x3e, (byte) 0x0f, (byte) 0x04, (byte) 0x19, (byte) 0x12},
            {(byte) 0xcb, (byte) 0xc0, (byte) 0xdd, (byte) 0xd6, (byte) 0xe7, (byte) 0xec, (byte) 0xf1, (byte) 0xfa, (byte) 0x93, (byte) 0x98, (byte) 0x85, (byte) 0x8e, (byte) 0xbf, (byte) 0xb4, (byte) 0xa9, (byte) 0xa2},
            {(byte) 0xf6, (byte) 0xfd, (byte) 0xe0, (byte) 0xeb, (byte) 0xda, (byte) 0xd1, (byte) 0xcc, (byte) 0xc7, (byte) 0xae, (byte) 0xa5, (byte) 0xb8, (byte) 0xb3, (byte) 0x82, (byte) 0x89, (byte) 0x94, (byte) 0x9f},
            {(byte) 0x46, (byte) 0x4d, (byte) 0x50, (byte) 0x5b, (byte) 0x6a, (byte) 0x61, (byte) 0x7c, (byte) 0x77, (byte) 0x1e, (byte) 0x15, (byte) 0x08, (byte) 0x03, (byte) 0x32, (byte) 0x39, (byte) 0x24, (byte) 0x2f},
            {(byte) 0x8d, (byte) 0x86, (byte) 0x9b, (byte) 0x90, (byte) 0xa1, (byte) 0xaa, (byte) 0xb7, (byte) 0xbc, (byte) 0xd5, (byte) 0xde, (byte) 0xc3, (byte) 0xc8, (byte) 0xf9, (byte) 0xf2, (byte) 0xef, (byte) 0xe4},
            {(byte) 0x3d, (byte) 0x36, (byte) 0x2b, (byte) 0x20, (byte) 0x11, (byte) 0x1a, (byte) 0x07, (byte) 0x0c, (byte) 0x65, (byte) 0x6e, (byte) 0x73, (byte) 0x78, (byte) 0x49, (byte) 0x42, (byte) 0x5f, (byte) 0x54},
            {(byte) 0xf7, (byte) 0xfc, (byte) 0xe1, (byte) 0xea, (byte) 0xdb, (byte) 0xd0, (byte) 0xcd, (byte) 0xc6, (byte) 0xaf, (byte) 0xa4, (byte) 0xb9, (byte) 0xb2, (byte) 0x83, (byte) 0x88, (byte) 0x95, (byte) 0x9e},
            {(byte) 0x47, (byte) 0x4c, (byte) 0x51, (byte) 0x5a, (byte) 0x6b, (byte) 0x60, (byte) 0x7d, (byte) 0x76, (byte) 0x1f, (byte) 0x14, (byte) 0x09, (byte) 0x02, (byte) 0x33, (byte) 0x38, (byte) 0x25, (byte) 0x2e},
            {(byte) 0x8c, (byte) 0x87, (byte) 0x9a, (byte) 0x91, (byte) 0xa0, (byte) 0xab, (byte) 0xb6, (byte) 0xbd, (byte) 0xd4, (byte) 0xdf, (byte) 0xc2, (byte) 0xc9, (byte) 0xf8, (byte) 0xf3, (byte) 0xee, (byte) 0xe5},
            {(byte) 0x3c, (byte) 0x37, (byte) 0x2a, (byte) 0x21, (byte) 0x10, (byte) 0x1b, (byte) 0x06, (byte) 0x0d, (byte) 0x64, (byte) 0x6f, (byte) 0x72, (byte) 0x79, (byte) 0x48, (byte) 0x43, (byte) 0x5e, (byte) 0x55},
            {(byte) 0x01, (byte) 0x0a, (byte) 0x17, (byte) 0x1c, (byte) 0x2d, (byte) 0x26, (byte) 0x3b, (byte) 0x30, (byte) 0x59, (byte) 0x52, (byte) 0x4f, (byte) 0x44, (byte) 0x75, (byte) 0x7e, (byte) 0x63, (byte) 0x68},
            {(byte) 0xb1, (byte) 0xba, (byte) 0xa7, (byte) 0xac, (byte) 0x9d, (byte) 0x96, (byte) 0x8b, (byte) 0x80, (byte) 0xe9, (byte) 0xe2, (byte) 0xff, (byte) 0xf4, (byte) 0xc5, (byte) 0xce, (byte) 0xd3, (byte) 0xd8},
            {(byte) 0x7a, (byte) 0x71, (byte) 0x6c, (byte) 0x67, (byte) 0x56, (byte) 0x5d, (byte) 0x40, (byte) 0x4b, (byte) 0x22, (byte) 0x29, (byte) 0x34, (byte) 0x3f, (byte) 0x0e, (byte) 0x05, (byte) 0x18, (byte) 0x13},
            {(byte) 0xca, (byte) 0xc1, (byte) 0xdc, (byte) 0xd7, (byte) 0xe6, (byte) 0xed, (byte) 0xf0, (byte) 0xfb, (byte) 0x92, (byte) 0x99, (byte) 0x84, (byte) 0x8f, (byte) 0xbe, (byte) 0xb5, (byte) 0xa8, (byte) 0xa3}};

    private static final byte[][] Gmul13 = {
            {(byte) 0x00, (byte) 0x0d, (byte) 0x1a, (byte) 0x17, (byte) 0x34, (byte) 0x39, (byte) 0x2e, (byte) 0x23, (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x7f, (byte) 0x5c, (byte) 0x51, (byte) 0x46, (byte) 0x4b},
            {(byte) 0xd0, (byte) 0xdd, (byte) 0xca, (byte) 0xc7, (byte) 0xe4, (byte) 0xe9, (byte) 0xfe, (byte) 0xf3, (byte) 0xb8, (byte) 0xb5, (byte) 0xa2, (byte) 0xaf, (byte) 0x8c, (byte) 0x81, (byte) 0x96, (byte) 0x9b},
            {(byte) 0xbb, (byte) 0xb6, (byte) 0xa1, (byte) 0xac, (byte) 0x8f, (byte) 0x82, (byte) 0x95, (byte) 0x98, (byte) 0xd3, (byte) 0xde, (byte) 0xc9, (byte) 0xc4, (byte) 0xe7, (byte) 0xea, (byte) 0xfd, (byte) 0xf0},
            {(byte) 0x6b, (byte) 0x66, (byte) 0x71, (byte) 0x7c, (byte) 0x5f, (byte) 0x52, (byte) 0x45, (byte) 0x48, (byte) 0x03, (byte) 0x0e, (byte) 0x19, (byte) 0x14, (byte) 0x37, (byte) 0x3a, (byte) 0x2d, (byte) 0x20},
            {(byte) 0x6d, (byte) 0x60, (byte) 0x77, (byte) 0x7a, (byte) 0x59, (byte) 0x54, (byte) 0x43, (byte) 0x4e, (byte) 0x05, (byte) 0x08, (byte) 0x1f, (byte) 0x12, (byte) 0x31, (byte) 0x3c, (byte) 0x2b, (byte) 0x26},
            {(byte) 0xbd, (byte) 0xb0, (byte) 0xa7, (byte) 0xaa, (byte) 0x89, (byte) 0x84, (byte) 0x93, (byte) 0x9e, (byte) 0xd5, (byte) 0xd8, (byte) 0xcf, (byte) 0xc2, (byte) 0xe1, (byte) 0xec, (byte) 0xfb, (byte) 0xf6},
            {(byte) 0xd6, (byte) 0xdb, (byte) 0xcc, (byte) 0xc1, (byte) 0xe2, (byte) 0xef, (byte) 0xf8, (byte) 0xf5, (byte) 0xbe, (byte) 0xb3, (byte) 0xa4, (byte) 0xa9, (byte) 0x8a, (byte) 0x87, (byte) 0x90, (byte) 0x9d},
            {(byte) 0x06, (byte) 0x0b, (byte) 0x1c, (byte) 0x11, (byte) 0x32, (byte) 0x3f, (byte) 0x28, (byte) 0x25, (byte) 0x6e, (byte) 0x63, (byte) 0x74, (byte) 0x79, (byte) 0x5a, (byte) 0x57, (byte) 0x40, (byte) 0x4d},
            {(byte) 0xda, (byte) 0xd7, (byte) 0xc0, (byte) 0xcd, (byte) 0xee, (byte) 0xe3, (byte) 0xf4, (byte) 0xf9, (byte) 0xb2, (byte) 0xbf, (byte) 0xa8, (byte) 0xa5, (byte) 0x86, (byte) 0x8b, (byte) 0x9c, (byte) 0x91},
            {(byte) 0x0a, (byte) 0x07, (byte) 0x10, (byte) 0x1d, (byte) 0x3e, (byte) 0x33, (byte) 0x24, (byte) 0x29, (byte) 0x62, (byte) 0x6f, (byte) 0x78, (byte) 0x75, (byte) 0x56, (byte) 0x5b, (byte) 0x4c, (byte) 0x41},
            {(byte) 0x61, (byte) 0x6c, (byte) 0x7b, (byte) 0x76, (byte) 0x55, (byte) 0x58, (byte) 0x4f, (byte) 0x42, (byte) 0x09, (byte) 0x04, (byte) 0x13, (byte) 0x1e, (byte) 0x3d, (byte) 0x30, (byte) 0x27, (byte) 0x2a},
            {(byte) 0xb1, (byte) 0xbc, (byte) 0xab, (byte) 0xa6, (byte) 0x85, (byte) 0x88, (byte) 0x9f, (byte) 0x92, (byte) 0xd9, (byte) 0xd4, (byte) 0xc3, (byte) 0xce, (byte) 0xed, (byte) 0xe0, (byte) 0xf7, (byte) 0xfa},
            {(byte) 0xb7, (byte) 0xba, (byte) 0xad, (byte) 0xa0, (byte) 0x83, (byte) 0x8e, (byte) 0x99, (byte) 0x94, (byte) 0xdf, (byte) 0xd2, (byte) 0xc5, (byte) 0xc8, (byte) 0xeb, (byte) 0xe6, (byte) 0xf1, (byte) 0xfc},
            {(byte) 0x67, (byte) 0x6a, (byte) 0x7d, (byte) 0x70, (byte) 0x53, (byte) 0x5e, (byte) 0x49, (byte) 0x44, (byte) 0x0f, (byte) 0x02, (byte) 0x15, (byte) 0x18, (byte) 0x3b, (byte) 0x36, (byte) 0x21, (byte) 0x2c},
            {(byte) 0x0c, (byte) 0x01, (byte) 0x16, (byte) 0x1b, (byte) 0x38, (byte) 0x35, (byte) 0x22, (byte) 0x2f, (byte) 0x64, (byte) 0x69, (byte) 0x7e, (byte) 0x73, (byte) 0x50, (byte) 0x5d, (byte) 0x4a, (byte) 0x47},
            {(byte) 0xdc, (byte) 0xd1, (byte) 0xc6, (byte) 0xcb, (byte) 0xe8, (byte) 0xe5, (byte) 0xf2, (byte) 0xff, (byte) 0xb4, (byte) 0xb9, (byte) 0xae, (byte) 0xa3, (byte) 0x80, (byte) 0x8d, (byte) 0x9a, (byte) 0x97}};

    private static final byte[][] Gmul14 = {
            {(byte) 0x00, (byte) 0x0e, (byte) 0x1c, (byte) 0x12, (byte) 0x38, (byte) 0x36, (byte) 0x24, (byte) 0x2a, (byte) 0x70, (byte) 0x7e, (byte) 0x6c, (byte) 0x62, (byte) 0x48, (byte) 0x46, (byte) 0x54, (byte) 0x5a},
            {(byte) 0xe0, (byte) 0xee, (byte) 0xfc, (byte) 0xf2, (byte) 0xd8, (byte) 0xd6, (byte) 0xc4, (byte) 0xca, (byte) 0x90, (byte) 0x9e, (byte) 0x8c, (byte) 0x82, (byte) 0xa8, (byte) 0xa6, (byte) 0xb4, (byte) 0xba},
            {(byte) 0xdb, (byte) 0xd5, (byte) 0xc7, (byte) 0xc9, (byte) 0xe3, (byte) 0xed, (byte) 0xff, (byte) 0xf1, (byte) 0xab, (byte) 0xa5, (byte) 0xb7, (byte) 0xb9, (byte) 0x93, (byte) 0x9d, (byte) 0x8f, (byte) 0x81},
            {(byte) 0x3b, (byte) 0x35, (byte) 0x27, (byte) 0x29, (byte) 0x03, (byte) 0x0d, (byte) 0x1f, (byte) 0x11, (byte) 0x4b, (byte) 0x45, (byte) 0x57, (byte) 0x59, (byte) 0x73, (byte) 0x7d, (byte) 0x6f, (byte) 0x61},
            {(byte) 0xad, (byte) 0xa3, (byte) 0xb1, (byte) 0xbf, (byte) 0x95, (byte) 0x9b, (byte) 0x89, (byte) 0x87, (byte) 0xdd, (byte) 0xd3, (byte) 0xc1, (byte) 0xcf, (byte) 0xe5, (byte) 0xeb, (byte) 0xf9, (byte) 0xf7},
            {(byte) 0x4d, (byte) 0x43, (byte) 0x51, (byte) 0x5f, (byte) 0x75, (byte) 0x7b, (byte) 0x69, (byte) 0x67, (byte) 0x3d, (byte) 0x33, (byte) 0x21, (byte) 0x2f, (byte) 0x05, (byte) 0x0b, (byte) 0x19, (byte) 0x17},
            {(byte) 0x76, (byte) 0x78, (byte) 0x6a, (byte) 0x64, (byte) 0x4e, (byte) 0x40, (byte) 0x52, (byte) 0x5c, (byte) 0x06, (byte) 0x08, (byte) 0x1a, (byte) 0x14, (byte) 0x3e, (byte) 0x30, (byte) 0x22, (byte) 0x2c},
            {(byte) 0x96, (byte) 0x98, (byte) 0x8a, (byte) 0x84, (byte) 0xae, (byte) 0xa0, (byte) 0xb2, (byte) 0xbc, (byte) 0xe6, (byte) 0xe8, (byte) 0xfa, (byte) 0xf4, (byte) 0xde, (byte) 0xd0, (byte) 0xc2, (byte) 0xcc},
            {(byte) 0x41, (byte) 0x4f, (byte) 0x5d, (byte) 0x53, (byte) 0x79, (byte) 0x77, (byte) 0x65, (byte) 0x6b, (byte) 0x31, (byte) 0x3f, (byte) 0x2d, (byte) 0x23, (byte) 0x09, (byte) 0x07, (byte) 0x15, (byte) 0x1b},
            {(byte) 0xa1, (byte) 0xaf, (byte) 0xbd, (byte) 0xb3, (byte) 0x99, (byte) 0x97, (byte) 0x85, (byte) 0x8b, (byte) 0xd1, (byte) 0xdf, (byte) 0xcd, (byte) 0xc3, (byte) 0xe9, (byte) 0xe7, (byte) 0xf5, (byte) 0xfb},
            {(byte) 0x9a, (byte) 0x94, (byte) 0x86, (byte) 0x88, (byte) 0xa2, (byte) 0xac, (byte) 0xbe, (byte) 0xb0, (byte) 0xea, (byte) 0xe4, (byte) 0xf6, (byte) 0xf8, (byte) 0xd2, (byte) 0xdc, (byte) 0xce, (byte) 0xc0},
            {(byte) 0x7a, (byte) 0x74, (byte) 0x66, (byte) 0x68, (byte) 0x42, (byte) 0x4c, (byte) 0x5e, (byte) 0x50, (byte) 0x0a, (byte) 0x04, (byte) 0x16, (byte) 0x18, (byte) 0x32, (byte) 0x3c, (byte) 0x2e, (byte) 0x20},
            {(byte) 0xec, (byte) 0xe2, (byte) 0xf0, (byte) 0xfe, (byte) 0xd4, (byte) 0xda, (byte) 0xc8, (byte) 0xc6, (byte) 0x9c, (byte) 0x92, (byte) 0x80, (byte) 0x8e, (byte) 0xa4, (byte) 0xaa, (byte) 0xb8, (byte) 0xb6},
            {(byte) 0x0c, (byte) 0x02, (byte) 0x10, (byte) 0x1e, (byte) 0x34, (byte) 0x3a, (byte) 0x28, (byte) 0x26, (byte) 0x7c, (byte) 0x72, (byte) 0x60, (byte) 0x6e, (byte) 0x44, (byte) 0x4a, (byte) 0x58, (byte) 0x56},
            {(byte) 0x37, (byte) 0x39, (byte) 0x2b, (byte) 0x25, (byte) 0x0f, (byte) 0x01, (byte) 0x13, (byte) 0x1d, (byte) 0x47, (byte) 0x49, (byte) 0x5b, (byte) 0x55, (byte) 0x7f, (byte) 0x71, (byte) 0x63, (byte) 0x6d},
            {(byte) 0xd7, (byte) 0xd9, (byte) 0xcb, (byte) 0xc5, (byte) 0xef, (byte) 0xe1, (byte) 0xf3, (byte) 0xfd, (byte) 0xa7, (byte) 0xa9, (byte) 0xbb, (byte) 0xb5, (byte) 0x9f, (byte) 0x91, (byte) 0x83, (byte) 0x8d}};

    private static final byte[][] Sbox = {
            {(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
            {(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
            {(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
            {(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}};

    private static final byte[][] SboxInv = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e},
            {(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92},
            {(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b},
            {(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e},
            {(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b},
            {(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
            {(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}};

    public static void main(String[] args) throws IOException {
        File test = new File("C:/Users/Dtmcn/IdeaProjects/AESLibrary/src/test1.txt");
        Scanner sc = new Scanner((test));
        String currentKey = sc.nextLine();
        long startTime = System.currentTimeMillis();
        while(sc.hasNextLine()){
            String currentText = sc.nextLine();
            byte[] givenKey = new byte[currentKey.length() / 2];
            byte[] givenText = new byte[currentText.length() / 2];
            for (int i = 0; i < givenText.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(currentText.substring(index, index + 2), 16);
                givenText[i] = (byte) j;
            }
            for (int i = 0; i < givenKey.length; i++) {
                int index = i * 2;
                int j = Integer.parseInt(currentKey.substring(index, index + 2), 16);
                givenKey[i] = (byte) j;
            }
            AESFunctions a = new AESFunctions();
            a.test(givenText, givenKey);
        }
        long endTime = System.currentTimeMillis();
        System.out.println("Execution time in Millis: " + (endTime-startTime));
    }

    private int SubWord(int word) {
        int newWord = 0;
        newWord ^= (int) sboxTransform((byte) (word >>> 24)) & 0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff0000) >>> 16)) &
                0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) ((word & 0xff00) >>> 8)) &
                0x000000ff;
        newWord <<= 8;

        newWord ^= (int) sboxTransform((byte) (word & 0xff)) & 0x000000ff;

        return newWord;
    }

    private int RotWord(int word) {
        return ((word << 8) ^ ((word >> 24) & 0x000000ff));
    }

    private int toWord(byte b1, byte b2, byte b3, byte b4) {
        byte[] temp = {b1, b2, b3, b4};
        return ByteBuffer.wrap(temp).getInt();
    }

    private int[] KeyExpansion(byte temp[], int expandedKey[]) {
        int iTemp;
        int i = 0;
        byte[] key = Arrays.copyOf(temp, temp.length);
        while (i < Nk) {
            expandedKey[i] = toWord(key[4 * i], key[(4 * i) + 1], key[(4 * i) + 2], key[(4 * i) + 3]);
            i++;
        }

        i = Nk;

        while (i < Nb * (NumRounds + 1)) {
            iTemp = expandedKey[i - 1];
            if (i % Nk == 0) {
                iTemp = (SubWord(RotWord(iTemp)) ^ Rcon[i / Nk]);
            }
            expandedKey[i] = (expandedKey[i - Nk] ^ iTemp);
            i++;
        }
        return expandedKey;
    }

    private int[] CreateKeyExpansion(byte key[]) {
        int[] w = new int[Nb * (NumRounds + 1)];
        int[] wTemp = KeyExpansion(key, w);
        return wTemp;
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte sboxTransform(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Sbox[bUpper][bLower];
    }

    private byte invSboxTransform(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return SboxInv[bUpper][bLower];
    }

    private byte gmul2(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul2[bUpper][bLower];
    }

    private byte gmul3(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul3[bUpper][bLower];
    }

    private byte gmul9(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul9[bUpper][bLower];
    }

    private byte gmul11(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul11[bUpper][bLower];
    }

    private byte gmul13(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul13[bUpper][bLower];
    }

    private byte gmul14(byte value) {
        byte bUpper, bLower;
        bUpper = (byte) ((byte) (value >> 4) & 0x0f);
        bLower = (byte) (value & 0x0f);
        return Gmul14[bUpper][bLower];
    }

    private byte xor4Bytes(byte b1, byte b2, byte b3, byte b4) {
        byte bResult1 = (byte) (b1 ^ b2);
        byte bResult2 = (byte) (bResult1 ^ b3);
        byte bResult3 = (byte) (bResult2 ^ b4);
        return bResult3;
    }

    private byte[] ByteArrayXOR(byte[] one, byte[] two) {
        byte[] three = new byte[one.length];
        for (int i = 0; i < three.length; i++) {
            three[i] = (byte) (one[i] ^ two[i]);
        }
        return three;
    }

    private byte[] Encrypt(byte[] plainText, byte[] key, int[] expandedKey) {
        byte[][] state;
        // Create one state
        state = CreateState(plainText);
        // Encrypt the state
        state = EncryptState(state, expandedKey);
        // Output encrypted block
        System.out.print("Encrypted Text: ");
        OutputState(state);
        System.out.println();
        byte[] flatState = new byte[Nb * Nb];

        System.arraycopy(state[0], 0, flatState, 0, state[0].length);
        System.arraycopy(state[1], 0, flatState, 4, state[1].length);
        System.arraycopy(state[2], 0, flatState, 8, state[2].length);
        System.arraycopy(state[3], 0, flatState, 12, state[3].length);
        return flatState;
    }

    private byte[] Decrypt(byte[] plainText, byte[] key, int[] expandedKey) {
        byte[][] state;
        // Create one state
        state = CreateState(plainText);
        // Decrypt the state
        state = DecryptState(state, expandedKey);
        // Output encrypted block
        System.out.print("Decrypted Text: ");
        OutputState(state);
        System.out.println();
        byte[] flatState = new byte[Nb * Nb];

        System.arraycopy(state[0], 0, flatState, 0, state[0].length);
        System.arraycopy(state[1], 0, flatState, 4, state[1].length);
        System.arraycopy(state[2], 0, flatState, 8, state[2].length);
        System.arraycopy(state[3], 0, flatState, 12, state[3].length);
        return flatState;
    }

    private byte[][] SubBytes(byte state[][]) {
        for (int i = 0; i < state.length; i++)
            for (int j = 0; j < state[i].length; j++)
                state[i][j] = sboxTransform(state[i][j]);
        return state;
    }

    private byte[][] InvSubBytes(byte state[][]) {
        for (int i = 0; i < state.length; i++)
            for (int j = 0; j < state[i].length; j++)
                state[i][j] = invSboxTransform(state[i][j]);
        return state;
    }

    private byte[][] AddRoundKey(byte[][] state, int[] w, int round) {
        int realRound = round * 4;
        byte[] flatState = new byte[Nb * Nb];

        System.arraycopy(state[0], 0, flatState, 0, state[0].length);
        System.arraycopy(state[1], 0, flatState, 4, state[1].length);
        System.arraycopy(state[2], 0, flatState, 8, state[2].length);
        System.arraycopy(state[3], 0, flatState, 12, state[3].length);

        byte[] currentKey1 = ByteBuffer.allocate(4).putInt(w[realRound]).array();
        byte[] currentKey2 = ByteBuffer.allocate(4).putInt(w[realRound + 1]).array();
        byte[] currentKey3 = ByteBuffer.allocate(4).putInt(w[realRound + 2]).array();
        byte[] currentKey4 = ByteBuffer.allocate(4).putInt(w[realRound + 3]).array();
        byte[] currentKey = new byte[currentKey1.length + currentKey2.length + currentKey3.length + currentKey4.length];

        for (int h = 0; h < currentKey1.length; h++) {
            currentKey[h] = currentKey1[h];
        }

        for (int h = 0; h < currentKey2.length; h++) {
            currentKey[h + 4] = currentKey2[h];
        }

        for (int h = 0; h < currentKey3.length; h++) {
            currentKey[h + 8] = currentKey3[h];
        }

        for (int h = 0; h < currentKey4.length; h++) {
            currentKey[h + 12] = currentKey4[h];
        }

        System.out.println("Current key: " + bytesToHex(currentKey));
        System.out.println();

        byte[] result = ByteArrayXOR(flatState, currentKey);

        byte[][] stateNew = new byte[Nb][Nb];

        for (int k = 0; k < result.length; k++) {
            stateNew[k / 4][k % 4] = result[k];
        }
        return stateNew;
    }

    private byte[][] ShiftRows(byte[][] arr) {
        byte[][] nextArr = {
                {arr[0][0], arr[1][1], arr[2][2], arr[3][3]},
                {arr[1][0], arr[2][1], arr[3][2], arr[0][3]},
                {arr[2][0], arr[3][1], arr[0][2], arr[1][3]},
                {arr[3][0], arr[0][1], arr[1][2], arr[2][3]},
        };
        return nextArr;
    }

    private byte[][] InvShiftRows(byte[][] arr) {
        byte[][] nextArr = {
                {arr[0][0], arr[3][1], arr[2][2], arr[1][3]},
                {arr[1][0], arr[0][1], arr[3][2], arr[2][3]},
                {arr[2][0], arr[1][1], arr[0][2], arr[3][3]},
                {arr[3][0], arr[2][1], arr[1][2], arr[0][3]},
        };
        return nextArr;
    }

    private byte[][] MixColumns(byte[][] state) {
        byte[][] stateNew = new byte[state.length][state[0].length];
        stateNew[0][0] = xor4Bytes(gmul2(state[0][0]), gmul3(state[0][1]), state[0][2], state[0][3]);
        stateNew[0][1] = xor4Bytes(state[0][0], gmul2(state[0][1]), gmul3(state[0][2]), state[0][3]);
        stateNew[0][2] = xor4Bytes(state[0][0], state[0][1], gmul2(state[0][2]), gmul3(state[0][3]));
        stateNew[0][3] = xor4Bytes(gmul3(state[0][0]), state[0][1], state[0][2], gmul2(state[0][3]));

        stateNew[1][0] = xor4Bytes(gmul2(state[1][0]), gmul3(state[1][1]), state[1][2], state[1][3]);
        stateNew[1][1] = xor4Bytes(state[1][0], gmul2(state[1][1]), gmul3(state[1][2]), state[1][3]);
        stateNew[1][2] = xor4Bytes(state[1][0], state[1][1], gmul2(state[1][2]), gmul3(state[1][3]));
        stateNew[1][3] = xor4Bytes(gmul3(state[1][0]), state[1][1], state[1][2], gmul2(state[1][3]));

        stateNew[2][0] = xor4Bytes(gmul2(state[2][0]), gmul3(state[2][1]), state[2][2], state[2][3]);
        stateNew[2][1] = xor4Bytes(state[2][0], gmul2(state[2][1]), gmul3(state[2][2]), state[2][3]);
        stateNew[2][2] = xor4Bytes(state[2][0], state[2][1], gmul2(state[2][2]), gmul3(state[2][3]));
        stateNew[2][3] = xor4Bytes(gmul3(state[2][0]), state[2][1], state[2][2], gmul2(state[2][3]));

        stateNew[3][0] = xor4Bytes(gmul2(state[3][0]), gmul3(state[3][1]), state[3][2], state[3][3]);
        stateNew[3][1] = xor4Bytes(state[3][0], gmul2(state[3][1]), gmul3(state[3][2]), state[3][3]);
        stateNew[3][2] = xor4Bytes(state[3][0], state[3][1], gmul2(state[3][2]), gmul3(state[3][3]));
        stateNew[3][3] = xor4Bytes(gmul3(state[3][0]), state[3][1], state[3][2], gmul2(state[3][3]));
        return stateNew;
    }

    private byte[][] InvMixColumns(byte[][] state) {
        byte[][] stateNew = new byte[state.length][state[0].length];
        stateNew[0][0] = xor4Bytes(gmul14(state[0][0]), gmul11(state[0][1]), gmul13(state[0][2]), gmul9(state[0][3]));
        stateNew[0][1] = xor4Bytes(gmul9(state[0][0]), gmul14(state[0][1]), gmul11(state[0][2]), gmul13(state[0][3]));
        stateNew[0][2] = xor4Bytes(gmul13(state[0][0]), gmul9(state[0][1]), gmul14(state[0][2]), gmul11(state[0][3]));
        stateNew[0][3] = xor4Bytes(gmul11(state[0][0]), gmul13(state[0][1]), gmul9(state[0][2]), gmul14(state[0][3]));

        stateNew[1][0] = xor4Bytes(gmul14(state[1][0]), gmul11(state[1][1]), gmul13(state[1][2]), gmul9(state[1][3]));
        stateNew[1][1] = xor4Bytes(gmul9(state[1][0]), gmul14(state[1][1]), gmul11(state[1][2]), gmul13(state[1][3]));
        stateNew[1][2] = xor4Bytes(gmul13(state[1][0]), gmul9(state[1][1]), gmul14(state[1][2]), gmul11(state[1][3]));
        stateNew[1][3] = xor4Bytes(gmul11(state[1][0]), gmul13(state[1][1]), gmul9(state[1][2]), gmul14(state[1][3]));

        stateNew[2][0] = xor4Bytes(gmul14(state[2][0]), gmul11(state[2][1]), gmul13(state[2][2]), gmul9(state[2][3]));
        stateNew[2][1] = xor4Bytes(gmul9(state[2][0]), gmul14(state[2][1]), gmul11(state[2][2]), gmul13(state[2][3]));
        stateNew[2][2] = xor4Bytes(gmul13(state[2][0]), gmul9(state[2][1]), gmul14(state[2][2]), gmul11(state[2][3]));
        stateNew[2][3] = xor4Bytes(gmul11(state[2][0]), gmul13(state[2][1]), gmul9(state[2][2]), gmul14(state[2][3]));

        stateNew[3][0] = xor4Bytes(gmul14(state[3][0]), gmul11(state[3][1]), gmul13(state[3][2]), gmul9(state[3][3]));
        stateNew[3][1] = xor4Bytes(gmul9(state[3][0]), gmul14(state[3][1]), gmul11(state[3][2]), gmul13(state[3][3]));
        stateNew[3][2] = xor4Bytes(gmul13(state[3][0]), gmul9(state[3][1]), gmul14(state[3][2]), gmul11(state[3][3]));
        stateNew[3][3] = xor4Bytes(gmul11(state[3][0]), gmul13(state[3][1]), gmul9(state[3][2]), gmul14(state[3][3]));

        return stateNew;
    }

    private byte[][] CreateState(byte[] plaintext) {
        byte[][] state = new byte[Nb][Nb];
        for (int i = 0; i < plaintext.length; ++i) {
            state[i / 4][i % 4] = plaintext[i];
        }
        return state;
    }

    private byte[][] EncryptState(byte[][] state, int[] key) {
        byte[][] temp;
        temp = AddRoundKey(state, key, 0); // Initial key round
        System.out.print("AddRound: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        for (int j = 1; j <= NumRounds - 1; ++j) {
            temp = SubBytes(state);
            System.out.print("SubBytes: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = ShiftRows(state);
            System.out.print("ShiftRows: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = MixColumns(state);
            System.out.print("MixColumns: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = AddRoundKey(state, key, j);
            System.out.print("AddRound: ");
            OutputState(temp);
            state = temp;
            System.out.println();
        }

        // Leave out MixColumns for final round
        System.out.print("SubBytes: ");
        OutputState(temp);
        temp = SubBytes(state);
        System.out.println();
        state = temp;
        temp = ShiftRows(state);
        System.out.print("ShiftRows: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        temp = AddRoundKey(state, key, NumRounds);
        System.out.print("AddRound: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        return state;
    }

    private byte[][] DecryptState(byte[][] state, int[] key) {
        byte[][] temp;
        temp = AddRoundKey(state, key, NumRounds);
        System.out.print("AddRound: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        for (int round = (NumRounds - 1); round >= 1; round--) {
            System.out.print("Start of Round: ");
            OutputState(state);
            System.out.println();
            temp = InvShiftRows(state);
            System.out.print("InvShiftRows: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = InvSubBytes(state);
            System.out.print("InvSubBytes: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = AddRoundKey(state, key, round);
            System.out.print("AddRound: ");
            OutputState(temp);
            state = temp;
            System.out.println();
            temp = InvMixColumns(state);
            System.out.print("InvMixColumns: ");
            OutputState(temp);
            state = temp;
            System.out.println();
        }
        temp = InvShiftRows(state);
        System.out.print("InvShiftRows: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        temp = InvSubBytes(state);
        System.out.print("InvSubBytes: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        temp = AddRoundKey(state, key, 0);
        System.out.print("AddRound: ");
        OutputState(temp);
        state = temp;
        System.out.println();
        return state;
    }

    private void OutputState(byte[][] state) {
        for (int i = 0; i < state.length; ++i) {
            System.out.print(bytesToHex(state[i]));
        }
        System.out.println("");
    }

    private void test(byte[] givenText, byte[] givenKey) {
        System.out.println("Given Key:" + bytesToHex(givenKey));
        System.out.println();
        System.out.println("Given Text:" + bytesToHex(givenText));
        System.out.println();
        int[] expanded_key = CreateKeyExpansion(givenKey);
        byte[] encrypted = Encrypt(givenText, givenKey, expanded_key);
        byte[] decrypted = Decrypt(encrypted, givenKey, expanded_key);
    }
}