package gormcrypt

import "gorm.io/gorm"

// User is a copy-and-adapt example: tag encrypted columns, register callbacks
// once in main, use WhereTag / WhereTagMulti for search.
type User struct {
	gorm.Model
	Name       string
	Email      string `gormcrypt:"blind_index=email_index"`
	EmailIndex string
	Phone      string `gormcrypt:"blind_index=phone_index"`
	PhoneIndex string
	Nisn       string `gormcrypt:"blind_index=nisn_index,fast=true,bits=256"`
	NisnIndex  string
}

// WhereUserNisn is a thin scope wrapper (optional, for readability).
func WhereUserNisn(value string) func(*gorm.DB) *gorm.DB {
	return WhereTag(&User{}, "nisn", value)
}
