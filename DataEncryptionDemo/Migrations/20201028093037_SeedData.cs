﻿using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace DataEncryptionDemo.Migrations
{
    public partial class SeedData : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Nric",
                table: "Patients",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RawNric",
                table: "Patients",
                nullable: true);

            migrationBuilder.InsertData(
                table: "DataKeys",
                columns: new[] { "Id", "Key", "KeyAsString" },
                values: new object[] { 1, new byte[] { 124, 142, 254, 32, 252, 41, 233, 37, 79, 125, 255, 208, 86, 132, 131, 92, 248, 197, 74, 111, 211, 92, 146, 240, 160, 221, 4, 172, 95, 209, 140, 37, 151, 176, 37, 166, 116, 97, 61, 152, 103, 169, 205, 177, 151, 90, 155, 252, 103, 242, 207, 103, 193, 226, 169, 160, 4, 159, 75, 174, 77, 85, 208, 200, 160, 0, 36, 40, 43, 88, 248, 213, 210, 42, 119, 197, 174, 85, 107, 114, 165, 189, 127, 142, 106, 130, 68, 214, 68, 136, 80, 168, 216, 180, 70, 15, 196, 29, 247, 98, 236, 67, 21, 36, 125, 87, 247, 62, 198, 52, 206, 4, 182, 21, 119, 248, 233, 112, 147, 109, 209, 224, 55, 120, 196, 202, 163, 97, 149, 225, 187, 221, 200, 134, 196, 230, 247, 247, 195, 23, 107, 221, 66, 55, 240, 5, 236, 10, 104, 75, 128, 231, 249, 163, 213, 132, 54, 42, 22, 94, 174, 205, 32, 24, 88, 68, 175, 27, 69, 173, 21, 178, 233, 165, 142, 147, 182, 218, 176, 254, 235, 230, 70, 111, 36, 194, 19, 32, 69, 95, 5, 175, 5, 171, 210, 170, 191, 116, 178, 114, 73, 23, 50, 242, 18, 193, 254, 208, 171, 217, 29, 167, 220, 17, 223, 79, 154, 43, 247, 48, 57, 18, 114, 162, 88, 168, 126, 186, 88, 246, 150, 222, 43, 57, 88, 55, 7, 162, 234, 38, 198, 180, 65, 76, 76, 203, 43, 30, 62, 56, 97, 254, 241, 187, 78, 198 }, "CRubx4Qe/whFvafcbT2TvLtOP7tUZ33fHxDCc56dbYDRMO2BDL1w9pQvaTma/xRWCYA4HkLAuH2TMZD4OuVBkmnyQGxRuvs6owNKmBfrcoSzqgpLbA6smwxCzbsTf0q4ZyCUsrFzY4aES+pbsi5q0M13wBge9wW32UkzypwBTM/siW0Dsor3dChGn3haC0jWUzpaeEZIs6dlo/kR8Zv/X+werfbtRvlyJrpwG1VQcjgGTOo1yLDhtJ9DCa5fGsREPRjhAOjX4TL9iUOxvpQiS+rr6hwJRnrLA93grqRulD/mjKhU/CVzg22LkQBFQ3G+j8lKEXWPTLLbO1FjDnwwVA==" });

            migrationBuilder.InsertData(
                table: "Patients",
                columns: new[] { "Id", "Nric", "RawNric" },
                values: new object[] { 1, "v4quGJlCZ1Yvem4LpYa9HALRxs/ZJ+EDu2KtLtMy93M=", "0001-0001-0001" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "DataKeys",
                keyColumn: "Id",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "Patients",
                keyColumn: "Id",
                keyValue: 1);

            migrationBuilder.DropColumn(
                name: "Nric",
                table: "Patients");

            migrationBuilder.DropColumn(
                name: "RawNric",
                table: "Patients");
        }
    }
}
