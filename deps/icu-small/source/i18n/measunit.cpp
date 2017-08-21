// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
**********************************************************************
* Copyright (c) 2004-2016, International Business Machines
* Corporation and others.  All Rights Reserved.
**********************************************************************
* Author: Alan Liu
* Created: April 26, 2004
* Since: ICU 3.0
**********************************************************************
*/
#include "utypeinfo.h" // for 'typeid' to work

#include "unicode/measunit.h"

#if !UCONFIG_NO_FORMATTING

#include "unicode/uenum.h"
#include "ustrenum.h"
#include "cstring.h"
#include "uassert.h"

U_NAMESPACE_BEGIN

UOBJECT_DEFINE_RTTI_IMPLEMENTATION(MeasureUnit)

// All code between the "Start generated code" comment and
// the "End generated code" comment is auto generated code
// and must not be edited manually. For instructions on how to correctly
// update this code, refer to:
// http://site.icu-project.org/design/formatting/measureformat/updating-measure-unit
//
// Start generated code

static const int32_t gOffsets[] = {
    0,
    2,
    7,
    16,
    20,
    24,
    285,
    295,
    306,
    310,
    316,
    320,
    340,
    341,
    352,
    358,
    363,
    367,
    371,
    396
};

static const int32_t gIndexes[] = {
    0,
    2,
    7,
    16,
    20,
    24,
    24,
    34,
    45,
    49,
    55,
    59,
    79,
    80,
    91,
    97,
    102,
    106,
    110,
    135
};

// Must be sorted alphabetically.
static const char * const gTypes[] = {
    u8"acceleration",
    u8"angle",
    u8"area",
    u8"concentr",
    u8"consumption",
    u8"currency",
    u8"digital",
    u8"duration",
    u8"electric",
    u8"energy",
    u8"frequency",
    u8"length",
    u8"light",
    u8"mass",
    u8"power",
    u8"pressure",
    u8"speed",
    u8"temperature",
    u8"volume"
};

// Must be grouped by type and sorted alphabetically within each type.
static const char * const gSubTypes[] = {
    u8"g-force",
    u8"meter-per-second-squared",
    u8"arc-minute",
    u8"arc-second",
    u8"degree",
    u8"radian",
    u8"revolution",
    u8"acre",
    u8"hectare",
    u8"square-centimeter",
    u8"square-foot",
    u8"square-inch",
    u8"square-kilometer",
    u8"square-meter",
    u8"square-mile",
    u8"square-yard",
    u8"karat",
    u8"milligram-per-deciliter",
    u8"millimole-per-liter",
    u8"part-per-million",
    u8"liter-per-100kilometers",
    u8"liter-per-kilometer",
    u8"mile-per-gallon",
    u8"mile-per-gallon-imperial",
    u8"ADP",
    u8"AED",
    u8"AFA",
    u8"AFN",
    u8"ALL",
    u8"AMD",
    u8"ANG",
    u8"AOA",
    u8"AON",
    u8"AOR",
    u8"ARA",
    u8"ARP",
    u8"ARS",
    u8"ATS",
    u8"AUD",
    u8"AWG",
    u8"AYM",
    u8"AZM",
    u8"AZN",
    u8"BAD",
    u8"BAM",
    u8"BBD",
    u8"BDT",
    u8"BEC",
    u8"BEF",
    u8"BEL",
    u8"BGL",
    u8"BGN",
    u8"BHD",
    u8"BIF",
    u8"BMD",
    u8"BND",
    u8"BOB",
    u8"BOV",
    u8"BRC",
    u8"BRE",
    u8"BRL",
    u8"BRN",
    u8"BRR",
    u8"BSD",
    u8"BTN",
    u8"BWP",
    u8"BYB",
    u8"BYN",
    u8"BYR",
    u8"BZD",
    u8"CAD",
    u8"CDF",
    u8"CHC",
    u8"CHE",
    u8"CHF",
    u8"CHW",
    u8"CLF",
    u8"CLP",
    u8"CNY",
    u8"COP",
    u8"COU",
    u8"CRC",
    u8"CSD",
    u8"CSK",
    u8"CUC",
    u8"CUP",
    u8"CVE",
    u8"CYP",
    u8"CZK",
    u8"DDM",
    u8"DEM",
    u8"DJF",
    u8"DKK",
    u8"DOP",
    u8"DZD",
    u8"ECS",
    u8"ECV",
    u8"EEK",
    u8"EGP",
    u8"ERN",
    u8"ESA",
    u8"ESB",
    u8"ESP",
    u8"ETB",
    u8"EUR",
    u8"FIM",
    u8"FJD",
    u8"FKP",
    u8"FRF",
    u8"GBP",
    u8"GEK",
    u8"GEL",
    u8"GHC",
    u8"GHP",
    u8"GHS",
    u8"GIP",
    u8"GMD",
    u8"GNF",
    u8"GQE",
    u8"GRD",
    u8"GTQ",
    u8"GWP",
    u8"GYD",
    u8"HKD",
    u8"HNL",
    u8"HRD",
    u8"HRK",
    u8"HTG",
    u8"HUF",
    u8"IDR",
    u8"IEP",
    u8"ILS",
    u8"INR",
    u8"IQD",
    u8"IRR",
    u8"ISK",
    u8"ITL",
    u8"JMD",
    u8"JOD",
    u8"JPY",
    u8"KES",
    u8"KGS",
    u8"KHR",
    u8"KMF",
    u8"KPW",
    u8"KRW",
    u8"KWD",
    u8"KYD",
    u8"KZT",
    u8"LAK",
    u8"LBP",
    u8"LKR",
    u8"LRD",
    u8"LSL",
    u8"LTL",
    u8"LTT",
    u8"LUC",
    u8"LUF",
    u8"LUL",
    u8"LVL",
    u8"LVR",
    u8"LYD",
    u8"MAD",
    u8"MDL",
    u8"MGA",
    u8"MGF",
    u8"MKD",
    u8"MLF",
    u8"MMK",
    u8"MNT",
    u8"MOP",
    u8"MRO",
    u8"MTL",
    u8"MUR",
    u8"MVR",
    u8"MWK",
    u8"MXN",
    u8"MXV",
    u8"MYR",
    u8"MZM",
    u8"MZN",
    u8"NAD",
    u8"NGN",
    u8"NIO",
    u8"NLG",
    u8"NOK",
    u8"NPR",
    u8"NZD",
    u8"OMR",
    u8"PAB",
    u8"PEI",
    u8"PEN",
    u8"PES",
    u8"PGK",
    u8"PHP",
    u8"PKR",
    u8"PLN",
    u8"PLZ",
    u8"PTE",
    u8"PYG",
    u8"QAR",
    u8"ROL",
    u8"RON",
    u8"RSD",
    u8"RUB",
    u8"RUR",
    u8"RWF",
    u8"SAR",
    u8"SBD",
    u8"SCR",
    u8"SDD",
    u8"SDG",
    u8"SEK",
    u8"SGD",
    u8"SHP",
    u8"SIT",
    u8"SKK",
    u8"SLL",
    u8"SOS",
    u8"SRD",
    u8"SRG",
    u8"SSP",
    u8"STD",
    u8"SVC",
    u8"SYP",
    u8"SZL",
    u8"THB",
    u8"TJR",
    u8"TJS",
    u8"TMM",
    u8"TMT",
    u8"TND",
    u8"TOP",
    u8"TPE",
    u8"TRL",
    u8"TRY",
    u8"TTD",
    u8"TWD",
    u8"TZS",
    u8"UAH",
    u8"UAK",
    u8"UGX",
    u8"USD",
    u8"USN",
    u8"USS",
    u8"UYI",
    u8"UYU",
    u8"UZS",
    u8"VEB",
    u8"VEF",
    u8"VND",
    u8"VUV",
    u8"WST",
    u8"XAF",
    u8"XAG",
    u8"XAU",
    u8"XBA",
    u8"XBB",
    u8"XBC",
    u8"XBD",
    u8"XCD",
    u8"XDR",
    u8"XEU",
    u8"XOF",
    u8"XPD",
    u8"XPF",
    u8"XPT",
    u8"XSU",
    u8"XTS",
    u8"XUA",
    u8"XXX",
    u8"YDD",
    u8"YER",
    u8"YUM",
    u8"YUN",
    u8"ZAL",
    u8"ZAR",
    u8"ZMK",
    u8"ZMW",
    u8"ZRN",
    u8"ZRZ",
    u8"ZWD",
    u8"ZWL",
    u8"ZWN",
    u8"ZWR",
    u8"bit",
    u8"byte",
    u8"gigabit",
    u8"gigabyte",
    u8"kilobit",
    u8"kilobyte",
    u8"megabit",
    u8"megabyte",
    u8"terabit",
    u8"terabyte",
    u8"century",
    u8"day",
    u8"hour",
    u8"microsecond",
    u8"millisecond",
    u8"minute",
    u8"month",
    u8"nanosecond",
    u8"second",
    u8"week",
    u8"year",
    u8"ampere",
    u8"milliampere",
    u8"ohm",
    u8"volt",
    u8"calorie",
    u8"foodcalorie",
    u8"joule",
    u8"kilocalorie",
    u8"kilojoule",
    u8"kilowatt-hour",
    u8"gigahertz",
    u8"hertz",
    u8"kilohertz",
    u8"megahertz",
    u8"astronomical-unit",
    u8"centimeter",
    u8"decimeter",
    u8"fathom",
    u8"foot",
    u8"furlong",
    u8"inch",
    u8"kilometer",
    u8"light-year",
    u8"meter",
    u8"micrometer",
    u8"mile",
    u8"mile-scandinavian",
    u8"millimeter",
    u8"nanometer",
    u8"nautical-mile",
    u8"parsec",
    u8"picometer",
    u8"point",
    u8"yard",
    u8"lux",
    u8"carat",
    u8"gram",
    u8"kilogram",
    u8"metric-ton",
    u8"microgram",
    u8"milligram",
    u8"ounce",
    u8"ounce-troy",
    u8"pound",
    u8"stone",
    u8"ton",
    u8"gigawatt",
    u8"horsepower",
    u8"kilowatt",
    u8"megawatt",
    u8"milliwatt",
    u8"watt",
    u8"hectopascal",
    u8"inch-hg",
    u8"millibar",
    u8"millimeter-of-mercury",
    u8"pound-per-square-inch",
    u8"kilometer-per-hour",
    u8"knot",
    u8"meter-per-second",
    u8"mile-per-hour",
    u8"celsius",
    u8"fahrenheit",
    u8"generic",
    u8"kelvin",
    u8"acre-foot",
    u8"bushel",
    u8"centiliter",
    u8"cubic-centimeter",
    u8"cubic-foot",
    u8"cubic-inch",
    u8"cubic-kilometer",
    u8"cubic-meter",
    u8"cubic-mile",
    u8"cubic-yard",
    u8"cup",
    u8"cup-metric",
    u8"deciliter",
    u8"fluid-ounce",
    u8"gallon",
    u8"gallon-imperial",
    u8"hectoliter",
    u8"liter",
    u8"megaliter",
    u8"milliliter",
    u8"pint",
    u8"pint-metric",
    u8"quart",
    u8"tablespoon",
    u8"teaspoon"
};

// Must be sorted by first value and then second value.
static int32_t unitPerUnitToSingleUnit[][4] = {
        {327, 297, 16, 0},
        {329, 303, 16, 2},
        {331, 297, 16, 3},
        {331, 385, 4, 2},
        {331, 386, 4, 3},
        {346, 383, 3, 1},
        {349, 11, 15, 4},
        {388, 327, 4, 1}
};

MeasureUnit *MeasureUnit::createGForce(UErrorCode &status) {
    return MeasureUnit::create(0, 0, status);
}

MeasureUnit *MeasureUnit::createMeterPerSecondSquared(UErrorCode &status) {
    return MeasureUnit::create(0, 1, status);
}

MeasureUnit *MeasureUnit::createArcMinute(UErrorCode &status) {
    return MeasureUnit::create(1, 0, status);
}

MeasureUnit *MeasureUnit::createArcSecond(UErrorCode &status) {
    return MeasureUnit::create(1, 1, status);
}

MeasureUnit *MeasureUnit::createDegree(UErrorCode &status) {
    return MeasureUnit::create(1, 2, status);
}

MeasureUnit *MeasureUnit::createRadian(UErrorCode &status) {
    return MeasureUnit::create(1, 3, status);
}

MeasureUnit *MeasureUnit::createRevolutionAngle(UErrorCode &status) {
    return MeasureUnit::create(1, 4, status);
}

MeasureUnit *MeasureUnit::createAcre(UErrorCode &status) {
    return MeasureUnit::create(2, 0, status);
}

MeasureUnit *MeasureUnit::createHectare(UErrorCode &status) {
    return MeasureUnit::create(2, 1, status);
}

MeasureUnit *MeasureUnit::createSquareCentimeter(UErrorCode &status) {
    return MeasureUnit::create(2, 2, status);
}

MeasureUnit *MeasureUnit::createSquareFoot(UErrorCode &status) {
    return MeasureUnit::create(2, 3, status);
}

MeasureUnit *MeasureUnit::createSquareInch(UErrorCode &status) {
    return MeasureUnit::create(2, 4, status);
}

MeasureUnit *MeasureUnit::createSquareKilometer(UErrorCode &status) {
    return MeasureUnit::create(2, 5, status);
}

MeasureUnit *MeasureUnit::createSquareMeter(UErrorCode &status) {
    return MeasureUnit::create(2, 6, status);
}

MeasureUnit *MeasureUnit::createSquareMile(UErrorCode &status) {
    return MeasureUnit::create(2, 7, status);
}

MeasureUnit *MeasureUnit::createSquareYard(UErrorCode &status) {
    return MeasureUnit::create(2, 8, status);
}

MeasureUnit *MeasureUnit::createKarat(UErrorCode &status) {
    return MeasureUnit::create(3, 0, status);
}

MeasureUnit *MeasureUnit::createMilligramPerDeciliter(UErrorCode &status) {
    return MeasureUnit::create(3, 1, status);
}

MeasureUnit *MeasureUnit::createMillimolePerLiter(UErrorCode &status) {
    return MeasureUnit::create(3, 2, status);
}

MeasureUnit *MeasureUnit::createPartPerMillion(UErrorCode &status) {
    return MeasureUnit::create(3, 3, status);
}

MeasureUnit *MeasureUnit::createLiterPer100Kilometers(UErrorCode &status) {
    return MeasureUnit::create(4, 0, status);
}

MeasureUnit *MeasureUnit::createLiterPerKilometer(UErrorCode &status) {
    return MeasureUnit::create(4, 1, status);
}

MeasureUnit *MeasureUnit::createMilePerGallon(UErrorCode &status) {
    return MeasureUnit::create(4, 2, status);
}

MeasureUnit *MeasureUnit::createMilePerGallonImperial(UErrorCode &status) {
    return MeasureUnit::create(4, 3, status);
}

// MeasureUnit *MeasureUnit::createEast(UErrorCode &status) {...}

// MeasureUnit *MeasureUnit::createNorth(UErrorCode &status) {...}

// MeasureUnit *MeasureUnit::createSouth(UErrorCode &status) {...}

// MeasureUnit *MeasureUnit::createWest(UErrorCode &status) {...}

MeasureUnit *MeasureUnit::createBit(UErrorCode &status) {
    return MeasureUnit::create(6, 0, status);
}

MeasureUnit *MeasureUnit::createByte(UErrorCode &status) {
    return MeasureUnit::create(6, 1, status);
}

MeasureUnit *MeasureUnit::createGigabit(UErrorCode &status) {
    return MeasureUnit::create(6, 2, status);
}

MeasureUnit *MeasureUnit::createGigabyte(UErrorCode &status) {
    return MeasureUnit::create(6, 3, status);
}

MeasureUnit *MeasureUnit::createKilobit(UErrorCode &status) {
    return MeasureUnit::create(6, 4, status);
}

MeasureUnit *MeasureUnit::createKilobyte(UErrorCode &status) {
    return MeasureUnit::create(6, 5, status);
}

MeasureUnit *MeasureUnit::createMegabit(UErrorCode &status) {
    return MeasureUnit::create(6, 6, status);
}

MeasureUnit *MeasureUnit::createMegabyte(UErrorCode &status) {
    return MeasureUnit::create(6, 7, status);
}

MeasureUnit *MeasureUnit::createTerabit(UErrorCode &status) {
    return MeasureUnit::create(6, 8, status);
}

MeasureUnit *MeasureUnit::createTerabyte(UErrorCode &status) {
    return MeasureUnit::create(6, 9, status);
}

MeasureUnit *MeasureUnit::createCentury(UErrorCode &status) {
    return MeasureUnit::create(7, 0, status);
}

MeasureUnit *MeasureUnit::createDay(UErrorCode &status) {
    return MeasureUnit::create(7, 1, status);
}

MeasureUnit *MeasureUnit::createHour(UErrorCode &status) {
    return MeasureUnit::create(7, 2, status);
}

MeasureUnit *MeasureUnit::createMicrosecond(UErrorCode &status) {
    return MeasureUnit::create(7, 3, status);
}

MeasureUnit *MeasureUnit::createMillisecond(UErrorCode &status) {
    return MeasureUnit::create(7, 4, status);
}

MeasureUnit *MeasureUnit::createMinute(UErrorCode &status) {
    return MeasureUnit::create(7, 5, status);
}

MeasureUnit *MeasureUnit::createMonth(UErrorCode &status) {
    return MeasureUnit::create(7, 6, status);
}

MeasureUnit *MeasureUnit::createNanosecond(UErrorCode &status) {
    return MeasureUnit::create(7, 7, status);
}

MeasureUnit *MeasureUnit::createSecond(UErrorCode &status) {
    return MeasureUnit::create(7, 8, status);
}

MeasureUnit *MeasureUnit::createWeek(UErrorCode &status) {
    return MeasureUnit::create(7, 9, status);
}

MeasureUnit *MeasureUnit::createYear(UErrorCode &status) {
    return MeasureUnit::create(7, 10, status);
}

MeasureUnit *MeasureUnit::createAmpere(UErrorCode &status) {
    return MeasureUnit::create(8, 0, status);
}

MeasureUnit *MeasureUnit::createMilliampere(UErrorCode &status) {
    return MeasureUnit::create(8, 1, status);
}

MeasureUnit *MeasureUnit::createOhm(UErrorCode &status) {
    return MeasureUnit::create(8, 2, status);
}

MeasureUnit *MeasureUnit::createVolt(UErrorCode &status) {
    return MeasureUnit::create(8, 3, status);
}

MeasureUnit *MeasureUnit::createCalorie(UErrorCode &status) {
    return MeasureUnit::create(9, 0, status);
}

MeasureUnit *MeasureUnit::createFoodcalorie(UErrorCode &status) {
    return MeasureUnit::create(9, 1, status);
}

MeasureUnit *MeasureUnit::createJoule(UErrorCode &status) {
    return MeasureUnit::create(9, 2, status);
}

MeasureUnit *MeasureUnit::createKilocalorie(UErrorCode &status) {
    return MeasureUnit::create(9, 3, status);
}

MeasureUnit *MeasureUnit::createKilojoule(UErrorCode &status) {
    return MeasureUnit::create(9, 4, status);
}

MeasureUnit *MeasureUnit::createKilowattHour(UErrorCode &status) {
    return MeasureUnit::create(9, 5, status);
}

MeasureUnit *MeasureUnit::createGigahertz(UErrorCode &status) {
    return MeasureUnit::create(10, 0, status);
}

MeasureUnit *MeasureUnit::createHertz(UErrorCode &status) {
    return MeasureUnit::create(10, 1, status);
}

MeasureUnit *MeasureUnit::createKilohertz(UErrorCode &status) {
    return MeasureUnit::create(10, 2, status);
}

MeasureUnit *MeasureUnit::createMegahertz(UErrorCode &status) {
    return MeasureUnit::create(10, 3, status);
}

MeasureUnit *MeasureUnit::createAstronomicalUnit(UErrorCode &status) {
    return MeasureUnit::create(11, 0, status);
}

MeasureUnit *MeasureUnit::createCentimeter(UErrorCode &status) {
    return MeasureUnit::create(11, 1, status);
}

MeasureUnit *MeasureUnit::createDecimeter(UErrorCode &status) {
    return MeasureUnit::create(11, 2, status);
}

MeasureUnit *MeasureUnit::createFathom(UErrorCode &status) {
    return MeasureUnit::create(11, 3, status);
}

MeasureUnit *MeasureUnit::createFoot(UErrorCode &status) {
    return MeasureUnit::create(11, 4, status);
}

MeasureUnit *MeasureUnit::createFurlong(UErrorCode &status) {
    return MeasureUnit::create(11, 5, status);
}

MeasureUnit *MeasureUnit::createInch(UErrorCode &status) {
    return MeasureUnit::create(11, 6, status);
}

MeasureUnit *MeasureUnit::createKilometer(UErrorCode &status) {
    return MeasureUnit::create(11, 7, status);
}

MeasureUnit *MeasureUnit::createLightYear(UErrorCode &status) {
    return MeasureUnit::create(11, 8, status);
}

MeasureUnit *MeasureUnit::createMeter(UErrorCode &status) {
    return MeasureUnit::create(11, 9, status);
}

MeasureUnit *MeasureUnit::createMicrometer(UErrorCode &status) {
    return MeasureUnit::create(11, 10, status);
}

MeasureUnit *MeasureUnit::createMile(UErrorCode &status) {
    return MeasureUnit::create(11, 11, status);
}

MeasureUnit *MeasureUnit::createMileScandinavian(UErrorCode &status) {
    return MeasureUnit::create(11, 12, status);
}

MeasureUnit *MeasureUnit::createMillimeter(UErrorCode &status) {
    return MeasureUnit::create(11, 13, status);
}

MeasureUnit *MeasureUnit::createNanometer(UErrorCode &status) {
    return MeasureUnit::create(11, 14, status);
}

MeasureUnit *MeasureUnit::createNauticalMile(UErrorCode &status) {
    return MeasureUnit::create(11, 15, status);
}

MeasureUnit *MeasureUnit::createParsec(UErrorCode &status) {
    return MeasureUnit::create(11, 16, status);
}

MeasureUnit *MeasureUnit::createPicometer(UErrorCode &status) {
    return MeasureUnit::create(11, 17, status);
}

MeasureUnit *MeasureUnit::createPoint(UErrorCode &status) {
    return MeasureUnit::create(11, 18, status);
}

MeasureUnit *MeasureUnit::createYard(UErrorCode &status) {
    return MeasureUnit::create(11, 19, status);
}

MeasureUnit *MeasureUnit::createLux(UErrorCode &status) {
    return MeasureUnit::create(12, 0, status);
}

MeasureUnit *MeasureUnit::createCarat(UErrorCode &status) {
    return MeasureUnit::create(13, 0, status);
}

MeasureUnit *MeasureUnit::createGram(UErrorCode &status) {
    return MeasureUnit::create(13, 1, status);
}

MeasureUnit *MeasureUnit::createKilogram(UErrorCode &status) {
    return MeasureUnit::create(13, 2, status);
}

MeasureUnit *MeasureUnit::createMetricTon(UErrorCode &status) {
    return MeasureUnit::create(13, 3, status);
}

MeasureUnit *MeasureUnit::createMicrogram(UErrorCode &status) {
    return MeasureUnit::create(13, 4, status);
}

MeasureUnit *MeasureUnit::createMilligram(UErrorCode &status) {
    return MeasureUnit::create(13, 5, status);
}

MeasureUnit *MeasureUnit::createOunce(UErrorCode &status) {
    return MeasureUnit::create(13, 6, status);
}

MeasureUnit *MeasureUnit::createOunceTroy(UErrorCode &status) {
    return MeasureUnit::create(13, 7, status);
}

MeasureUnit *MeasureUnit::createPound(UErrorCode &status) {
    return MeasureUnit::create(13, 8, status);
}

MeasureUnit *MeasureUnit::createStone(UErrorCode &status) {
    return MeasureUnit::create(13, 9, status);
}

MeasureUnit *MeasureUnit::createTon(UErrorCode &status) {
    return MeasureUnit::create(13, 10, status);
}

MeasureUnit *MeasureUnit::createGigawatt(UErrorCode &status) {
    return MeasureUnit::create(14, 0, status);
}

MeasureUnit *MeasureUnit::createHorsepower(UErrorCode &status) {
    return MeasureUnit::create(14, 1, status);
}

MeasureUnit *MeasureUnit::createKilowatt(UErrorCode &status) {
    return MeasureUnit::create(14, 2, status);
}

MeasureUnit *MeasureUnit::createMegawatt(UErrorCode &status) {
    return MeasureUnit::create(14, 3, status);
}

MeasureUnit *MeasureUnit::createMilliwatt(UErrorCode &status) {
    return MeasureUnit::create(14, 4, status);
}

MeasureUnit *MeasureUnit::createWatt(UErrorCode &status) {
    return MeasureUnit::create(14, 5, status);
}

MeasureUnit *MeasureUnit::createHectopascal(UErrorCode &status) {
    return MeasureUnit::create(15, 0, status);
}

MeasureUnit *MeasureUnit::createInchHg(UErrorCode &status) {
    return MeasureUnit::create(15, 1, status);
}

MeasureUnit *MeasureUnit::createMillibar(UErrorCode &status) {
    return MeasureUnit::create(15, 2, status);
}

MeasureUnit *MeasureUnit::createMillimeterOfMercury(UErrorCode &status) {
    return MeasureUnit::create(15, 3, status);
}

MeasureUnit *MeasureUnit::createPoundPerSquareInch(UErrorCode &status) {
    return MeasureUnit::create(15, 4, status);
}

MeasureUnit *MeasureUnit::createKilometerPerHour(UErrorCode &status) {
    return MeasureUnit::create(16, 0, status);
}

MeasureUnit *MeasureUnit::createKnot(UErrorCode &status) {
    return MeasureUnit::create(16, 1, status);
}

MeasureUnit *MeasureUnit::createMeterPerSecond(UErrorCode &status) {
    return MeasureUnit::create(16, 2, status);
}

MeasureUnit *MeasureUnit::createMilePerHour(UErrorCode &status) {
    return MeasureUnit::create(16, 3, status);
}

MeasureUnit *MeasureUnit::createCelsius(UErrorCode &status) {
    return MeasureUnit::create(17, 0, status);
}

MeasureUnit *MeasureUnit::createFahrenheit(UErrorCode &status) {
    return MeasureUnit::create(17, 1, status);
}

MeasureUnit *MeasureUnit::createGenericTemperature(UErrorCode &status) {
    return MeasureUnit::create(17, 2, status);
}

MeasureUnit *MeasureUnit::createKelvin(UErrorCode &status) {
    return MeasureUnit::create(17, 3, status);
}

MeasureUnit *MeasureUnit::createAcreFoot(UErrorCode &status) {
    return MeasureUnit::create(18, 0, status);
}

MeasureUnit *MeasureUnit::createBushel(UErrorCode &status) {
    return MeasureUnit::create(18, 1, status);
}

MeasureUnit *MeasureUnit::createCentiliter(UErrorCode &status) {
    return MeasureUnit::create(18, 2, status);
}

MeasureUnit *MeasureUnit::createCubicCentimeter(UErrorCode &status) {
    return MeasureUnit::create(18, 3, status);
}

MeasureUnit *MeasureUnit::createCubicFoot(UErrorCode &status) {
    return MeasureUnit::create(18, 4, status);
}

MeasureUnit *MeasureUnit::createCubicInch(UErrorCode &status) {
    return MeasureUnit::create(18, 5, status);
}

MeasureUnit *MeasureUnit::createCubicKilometer(UErrorCode &status) {
    return MeasureUnit::create(18, 6, status);
}

MeasureUnit *MeasureUnit::createCubicMeter(UErrorCode &status) {
    return MeasureUnit::create(18, 7, status);
}

MeasureUnit *MeasureUnit::createCubicMile(UErrorCode &status) {
    return MeasureUnit::create(18, 8, status);
}

MeasureUnit *MeasureUnit::createCubicYard(UErrorCode &status) {
    return MeasureUnit::create(18, 9, status);
}

MeasureUnit *MeasureUnit::createCup(UErrorCode &status) {
    return MeasureUnit::create(18, 10, status);
}

MeasureUnit *MeasureUnit::createCupMetric(UErrorCode &status) {
    return MeasureUnit::create(18, 11, status);
}

MeasureUnit *MeasureUnit::createDeciliter(UErrorCode &status) {
    return MeasureUnit::create(18, 12, status);
}

MeasureUnit *MeasureUnit::createFluidOunce(UErrorCode &status) {
    return MeasureUnit::create(18, 13, status);
}

MeasureUnit *MeasureUnit::createGallon(UErrorCode &status) {
    return MeasureUnit::create(18, 14, status);
}

MeasureUnit *MeasureUnit::createGallonImperial(UErrorCode &status) {
    return MeasureUnit::create(18, 15, status);
}

MeasureUnit *MeasureUnit::createHectoliter(UErrorCode &status) {
    return MeasureUnit::create(18, 16, status);
}

MeasureUnit *MeasureUnit::createLiter(UErrorCode &status) {
    return MeasureUnit::create(18, 17, status);
}

MeasureUnit *MeasureUnit::createMegaliter(UErrorCode &status) {
    return MeasureUnit::create(18, 18, status);
}

MeasureUnit *MeasureUnit::createMilliliter(UErrorCode &status) {
    return MeasureUnit::create(18, 19, status);
}

MeasureUnit *MeasureUnit::createPint(UErrorCode &status) {
    return MeasureUnit::create(18, 20, status);
}

MeasureUnit *MeasureUnit::createPintMetric(UErrorCode &status) {
    return MeasureUnit::create(18, 21, status);
}

MeasureUnit *MeasureUnit::createQuart(UErrorCode &status) {
    return MeasureUnit::create(18, 22, status);
}

MeasureUnit *MeasureUnit::createTablespoon(UErrorCode &status) {
    return MeasureUnit::create(18, 23, status);
}

MeasureUnit *MeasureUnit::createTeaspoon(UErrorCode &status) {
    return MeasureUnit::create(18, 24, status);
}

// End generated code

static int32_t binarySearch(
        const char * const * array, int32_t start, int32_t end, const char * key) {
    while (start < end) {
        int32_t mid = (start + end) / 2;
        int32_t cmp = uprv_strcmp(array[mid], key);
        if (cmp < 0) {
            start = mid + 1;
            continue;
        }
        if (cmp == 0) {
            return mid;
        }
        end = mid;
    }
    return -1;
}

MeasureUnit::MeasureUnit(const MeasureUnit &other)
        : fTypeId(other.fTypeId), fSubTypeId(other.fSubTypeId) {
    uprv_strcpy(fCurrency, other.fCurrency);
}

MeasureUnit &MeasureUnit::operator=(const MeasureUnit &other) {
    if (this == &other) {
        return *this;
    }
    fTypeId = other.fTypeId;
    fSubTypeId = other.fSubTypeId;
    uprv_strcpy(fCurrency, other.fCurrency);
    return *this;
}

UObject *MeasureUnit::clone() const {
    return new MeasureUnit(*this);
}

MeasureUnit::~MeasureUnit() {
}

const char *MeasureUnit::getType() const {
    return gTypes[fTypeId];
}

const char *MeasureUnit::getSubtype() const {
    return fCurrency[0] == 0 ? gSubTypes[getOffset()] : fCurrency;
}

UBool MeasureUnit::operator==(const UObject& other) const {
    if (this == &other) {  // Same object, equal
        return TRUE;
    }
    if (typeid(*this) != typeid(other)) { // Different types, not equal
        return FALSE;
    }
    const MeasureUnit &rhs = static_cast<const MeasureUnit&>(other);
    return (
            fTypeId == rhs.fTypeId
            && fSubTypeId == rhs.fSubTypeId
            && uprv_strcmp(fCurrency, rhs.fCurrency) == 0);
}

int32_t MeasureUnit::getIndex() const {
    return gIndexes[fTypeId] + fSubTypeId;
}

int32_t MeasureUnit::getAvailable(
        MeasureUnit *dest,
        int32_t destCapacity,
        UErrorCode &errorCode) {
    if (U_FAILURE(errorCode)) {
        return 0;
    }
    if (destCapacity < UPRV_LENGTHOF(gSubTypes)) {
        errorCode = U_BUFFER_OVERFLOW_ERROR;
        return UPRV_LENGTHOF(gSubTypes);
    }
    int32_t idx = 0;
    for (int32_t typeIdx = 0; typeIdx < UPRV_LENGTHOF(gTypes); ++typeIdx) {
        int32_t len = gOffsets[typeIdx + 1] - gOffsets[typeIdx];
        for (int32_t subTypeIdx = 0; subTypeIdx < len; ++subTypeIdx) {
            dest[idx].setTo(typeIdx, subTypeIdx);
            ++idx;
        }
    }
    U_ASSERT(idx == UPRV_LENGTHOF(gSubTypes));
    return UPRV_LENGTHOF(gSubTypes);
}

int32_t MeasureUnit::getAvailable(
        const char *type,
        MeasureUnit *dest,
        int32_t destCapacity,
        UErrorCode &errorCode) {
    if (U_FAILURE(errorCode)) {
        return 0;
    }
    int32_t typeIdx = binarySearch(gTypes, 0, UPRV_LENGTHOF(gTypes), type);
    if (typeIdx == -1) {
        return 0;
    }
    int32_t len = gOffsets[typeIdx + 1] - gOffsets[typeIdx];
    if (destCapacity < len) {
        errorCode = U_BUFFER_OVERFLOW_ERROR;
        return len;
    }
    for (int subTypeIdx = 0; subTypeIdx < len; ++subTypeIdx) {
        dest[subTypeIdx].setTo(typeIdx, subTypeIdx);
    }
    return len;
}

StringEnumeration* MeasureUnit::getAvailableTypes(UErrorCode &errorCode) {
    UEnumeration *uenum = uenum_openCharStringsEnumeration(
            gTypes, UPRV_LENGTHOF(gTypes), &errorCode);
    if (U_FAILURE(errorCode)) {
        uenum_close(uenum);
        return NULL;
    }
    StringEnumeration *result = new UStringEnumeration(uenum);
    if (result == NULL) {
        errorCode = U_MEMORY_ALLOCATION_ERROR;
        uenum_close(uenum);
        return NULL;
    }
    return result;
}

int32_t MeasureUnit::getIndexCount() {
    return gIndexes[UPRV_LENGTHOF(gIndexes) - 1];
}

int32_t MeasureUnit::internalGetIndexForTypeAndSubtype(const char *type, const char *subtype) {
    int32_t t = binarySearch(gTypes, 0, UPRV_LENGTHOF(gTypes), type);
    if (t < 0) {
        return t;
    }
    int32_t st = binarySearch(gSubTypes, gOffsets[t], gOffsets[t + 1], subtype);
    if (st < 0) {
        return st;
    }
    return gIndexes[t] + st - gOffsets[t];
}

MeasureUnit *MeasureUnit::resolveUnitPerUnit(
        const MeasureUnit &unit, const MeasureUnit &perUnit) {
    int32_t unitOffset = unit.getOffset();
    int32_t perUnitOffset = perUnit.getOffset();

    // binary search for (unitOffset, perUnitOffset)
    int32_t start = 0;
    int32_t end = UPRV_LENGTHOF(unitPerUnitToSingleUnit);
    while (start < end) {
        int32_t mid = (start + end) / 2;
        int32_t *midRow = unitPerUnitToSingleUnit[mid];
        if (unitOffset < midRow[0]) {
            end = mid;
        } else if (unitOffset > midRow[0]) {
            start = mid + 1;
        } else if (perUnitOffset < midRow[1]) {
            end = mid;
        } else if (perUnitOffset > midRow[1]) {
            start = mid + 1;
        } else {
            // We found a resolution for our unit / per-unit combo
            // return it.
            return new MeasureUnit(midRow[2], midRow[3]);
        }
    }
    return NULL;
}

MeasureUnit *MeasureUnit::create(int typeId, int subTypeId, UErrorCode &status) {
    if (U_FAILURE(status)) {
        return NULL;
    }
    MeasureUnit *result = new MeasureUnit(typeId, subTypeId);
    if (result == NULL) {
        status = U_MEMORY_ALLOCATION_ERROR;
    }
    return result;
}

void MeasureUnit::initTime(const char *timeId) {
    int32_t result = binarySearch(gTypes, 0, UPRV_LENGTHOF(gTypes), u8"duration");
    U_ASSERT(result != -1);
    fTypeId = result;
    result = binarySearch(gSubTypes, gOffsets[fTypeId], gOffsets[fTypeId + 1], timeId);
    U_ASSERT(result != -1);
    fSubTypeId = result - gOffsets[fTypeId];
}

void MeasureUnit::initCurrency(const char *isoCurrency) {
    int32_t result = binarySearch(gTypes, 0, UPRV_LENGTHOF(gTypes), u8"currency");
    U_ASSERT(result != -1);
    fTypeId = result;
    result = binarySearch(
            gSubTypes, gOffsets[fTypeId], gOffsets[fTypeId + 1], isoCurrency);
    if (result != -1) {
        fSubTypeId = result - gOffsets[fTypeId];
    } else {
        uprv_strncpy(fCurrency, isoCurrency, UPRV_LENGTHOF(fCurrency));
        fCurrency[3] = 0;
    }
}

void MeasureUnit::setTo(int32_t typeId, int32_t subTypeId) {
    fTypeId = typeId;
    fSubTypeId = subTypeId;
    fCurrency[0] = 0;
}

int32_t MeasureUnit::getOffset() const {
    return gOffsets[fTypeId] + fSubTypeId;
}

U_NAMESPACE_END

#endif /* !UNCONFIG_NO_FORMATTING */
