package netinfo

import "math"

// Region is a federal subject of Russia with the approximate location of its capital.
type Region struct {
	Code string // ISO 3166-2
	RU   string
	EN   string
	Lat  float64
	Lon  float64
}

// regions lists the subjects used for coarse geolocation. Moscow and
// St. Petersburg are matched by radius first, everything else by the nearest
// capital within maxRegionKm.
var regions = []Region{
	{"RU-MOW", "Москва", "Moscow", 55.75, 37.62},
	{"RU-SPE", "Санкт-Петербург", "Saint Petersburg", 59.94, 30.31},
	{"RU-MOS", "Московская область", "Moscow Oblast", 55.55, 37.70},
	{"RU-LEN", "Ленинградская область", "Leningrad Oblast", 59.57, 30.13},
	{"RU-AD", "Адыгея", "Adygea", 44.61, 40.10},
	{"RU-AL", "Республика Алтай", "Altai Republic", 51.96, 85.96},
	{"RU-ALT", "Алтайский край", "Altai Krai", 53.35, 83.78},
	{"RU-AMU", "Амурская область", "Amur Oblast", 50.29, 127.53},
	{"RU-ARK", "Архангельская область", "Arkhangelsk Oblast", 64.54, 40.54},
	{"RU-AST", "Астраханская область", "Astrakhan Oblast", 46.35, 48.04},
	{"RU-BA", "Башкортостан", "Bashkortostan", 54.73, 55.96},
	{"RU-BEL", "Белгородская область", "Belgorod Oblast", 50.60, 36.59},
	{"RU-BRY", "Брянская область", "Bryansk Oblast", 53.24, 34.36},
	{"RU-BU", "Бурятия", "Buryatia", 51.83, 107.58},
	{"RU-CE", "Чечня", "Chechnya", 43.32, 45.69},
	{"RU-CHE", "Челябинская область", "Chelyabinsk Oblast", 55.16, 61.40},
	{"RU-CHU", "Чукотский АО", "Chukotka", 64.73, 177.51},
	{"RU-CU", "Чувашия", "Chuvashia", 56.15, 47.25},
	{"RU-DA", "Дагестан", "Dagestan", 42.98, 47.50},
	{"RU-IN", "Ингушетия", "Ingushetia", 43.17, 44.81},
	{"RU-IRK", "Иркутская область", "Irkutsk Oblast", 52.29, 104.30},
	{"RU-IVA", "Ивановская область", "Ivanovo Oblast", 57.00, 40.97},
	{"RU-KB", "Кабардино-Балкария", "Kabardino-Balkaria", 43.49, 43.61},
	{"RU-KGD", "Калининградская область", "Kaliningrad Oblast", 54.71, 20.51},
	{"RU-KL", "Калмыкия", "Kalmykia", 46.31, 44.26},
	{"RU-KLU", "Калужская область", "Kaluga Oblast", 54.51, 36.26},
	{"RU-KAM", "Камчатский край", "Kamchatka Krai", 53.02, 158.65},
	{"RU-KC", "Карачаево-Черкесия", "Karachay-Cherkessia", 44.23, 42.05},
	{"RU-KR", "Карелия", "Karelia", 61.79, 34.36},
	{"RU-KEM", "Кемеровская область", "Kemerovo Oblast", 55.35, 86.09},
	{"RU-KHA", "Хабаровский край", "Khabarovsk Krai", 48.48, 135.08},
	{"RU-KK", "Хакасия", "Khakassia", 53.72, 91.44},
	{"RU-KHM", "Ханты-Мансийский АО", "Khanty-Mansi AO", 61.00, 69.02},
	{"RU-KIR", "Кировская область", "Kirov Oblast", 58.60, 49.66},
	{"RU-KO", "Коми", "Komi", 61.67, 50.81},
	{"RU-KOS", "Костромская область", "Kostroma Oblast", 57.77, 40.93},
	{"RU-KDA", "Краснодарский край", "Krasnodar Krai", 45.04, 38.98},
	{"RU-KYA", "Красноярский край", "Krasnoyarsk Krai", 56.01, 92.85},
	{"RU-KGN", "Курганская область", "Kurgan Oblast", 55.44, 65.34},
	{"RU-KRS", "Курская область", "Kursk Oblast", 51.73, 36.19},
	{"RU-LIP", "Липецкая область", "Lipetsk Oblast", 52.61, 39.59},
	{"RU-MAG", "Магаданская область", "Magadan Oblast", 59.57, 150.80},
	{"RU-ME", "Марий Эл", "Mari El", 56.63, 47.89},
	{"RU-MO", "Мордовия", "Mordovia", 54.18, 45.18},
	{"RU-MUR", "Мурманская область", "Murmansk Oblast", 68.97, 33.07},
	{"RU-NEN", "Ненецкий АО", "Nenets AO", 67.64, 53.01},
	{"RU-NIZ", "Нижегородская область", "Nizhny Novgorod Oblast", 56.33, 44.00},
	{"RU-NGR", "Новгородская область", "Novgorod Oblast", 58.52, 31.27},
	{"RU-NVS", "Новосибирская область", "Novosibirsk Oblast", 55.03, 82.92},
	{"RU-OMS", "Омская область", "Omsk Oblast", 54.99, 73.37},
	{"RU-ORE", "Оренбургская область", "Orenburg Oblast", 51.77, 55.10},
	{"RU-ORL", "Орловская область", "Oryol Oblast", 52.97, 36.06},
	{"RU-PNZ", "Пензенская область", "Penza Oblast", 53.20, 45.02},
	{"RU-PER", "Пермский край", "Perm Krai", 58.01, 56.25},
	{"RU-PRI", "Приморский край", "Primorsky Krai", 43.12, 131.89},
	{"RU-PSK", "Псковская область", "Pskov Oblast", 57.82, 28.33},
	{"RU-ROS", "Ростовская область", "Rostov Oblast", 47.24, 39.71},
	{"RU-RYA", "Рязанская область", "Ryazan Oblast", 54.63, 39.74},
	{"RU-SA", "Якутия", "Sakha (Yakutia)", 62.03, 129.73},
	{"RU-SAK", "Сахалинская область", "Sakhalin Oblast", 46.96, 142.73},
	{"RU-SAM", "Самарская область", "Samara Oblast", 53.20, 50.15},
	{"RU-SAR", "Саратовская область", "Saratov Oblast", 51.53, 46.03},
	{"RU-SE", "Северная Осетия", "North Ossetia", 43.02, 44.68},
	{"RU-SMO", "Смоленская область", "Smolensk Oblast", 54.78, 32.05},
	{"RU-STA", "Ставропольский край", "Stavropol Krai", 45.04, 41.97},
	{"RU-SVE", "Свердловская область", "Sverdlovsk Oblast", 56.84, 60.61},
	{"RU-TAM", "Тамбовская область", "Tambov Oblast", 52.72, 41.45},
	{"RU-TA", "Татарстан", "Tatarstan", 55.79, 49.12},
	{"RU-TOM", "Томская область", "Tomsk Oblast", 56.48, 84.95},
	{"RU-TUL", "Тульская область", "Tula Oblast", 54.19, 37.62},
	{"RU-TVE", "Тверская область", "Tver Oblast", 56.86, 35.90},
	{"RU-TYU", "Тюменская область", "Tyumen Oblast", 57.15, 65.53},
	{"RU-TY", "Тыва", "Tuva", 51.72, 94.45},
	{"RU-UD", "Удмуртия", "Udmurtia", 56.85, 53.20},
	{"RU-ULY", "Ульяновская область", "Ulyanovsk Oblast", 54.32, 48.40},
	{"RU-VLA", "Владимирская область", "Vladimir Oblast", 56.13, 40.41},
	{"RU-VGG", "Волгоградская область", "Volgograd Oblast", 48.71, 44.51},
	{"RU-VLG", "Вологодская область", "Vologda Oblast", 59.22, 39.89},
	{"RU-VOR", "Воронежская область", "Voronezh Oblast", 51.66, 39.20},
	{"RU-YAN", "Ямало-Ненецкий АО", "Yamalo-Nenets AO", 66.53, 66.60},
	{"RU-YAR", "Ярославская область", "Yaroslavl Oblast", 57.63, 39.87},
	{"RU-YEV", "Еврейская АО", "Jewish AO", 48.79, 132.92},
	{"RU-ZAB", "Забайкальский край", "Zabaykalsky Krai", 52.03, 113.50},
}

// extraPoints add large cities far from their regional capital, which would
// otherwise be attributed to a neighbouring region.
var extraPoints = []struct {
	Code     string
	Lat, Lon float64
}{
	{"RU-KDA", 43.59, 39.72},  // Sochi
	{"RU-KDA", 44.72, 37.77},  // Novorossiysk
	{"RU-SAM", 53.51, 49.42},  // Togliatti
	{"RU-KHM", 61.25, 73.40},  // Surgut
	{"RU-KHM", 60.94, 76.57},  // Nizhnevartovsk
	{"RU-KYA", 69.35, 88.20},  // Norilsk
	{"RU-CHE", 53.41, 58.98},  // Magnitogorsk
	{"RU-TA", 55.74, 52.40},   // Naberezhnye Chelny
	{"RU-VLG", 59.13, 37.90},  // Cherepovets
	{"RU-KEM", 53.76, 87.12},  // Novokuznetsk
	{"RU-IRK", 56.15, 101.63}, // Bratsk
	{"RU-KHA", 50.55, 137.01}, // Komsomolsk-on-Amur
	{"RU-PRI", 42.82, 132.87}, // Nakhodka
	{"RU-SA", 62.53, 113.96},  // Mirny
	{"RU-KO", 67.50, 64.05},   // Vorkuta
	{"RU-YAN", 66.08, 76.68},  // Novy Urengoy
	{"RU-STA", 44.04, 43.06},  // Pyatigorsk
	{"RU-ROS", 47.71, 40.21},  // Novocherkassk / Shakhty area
	{"RU-MUR", 67.61, 33.67},  // Kirovsk/Apatity
}

const maxRegionKm = 700

// cityRadius matches federal cities before the nearest-capital search.
var cityRadius = map[string]float64{"RU-MOW": 30, "RU-SPE": 25}

// NearestRegion returns the federal subject for a coordinate, or nil when no
// capital is close enough.
func NearestRegion(lat, lon float64) *Region {
	for i := range regions {
		r := &regions[i]
		if rad, ok := cityRadius[r.Code]; ok && haversine(lat, lon, r.Lat, r.Lon) <= rad {
			return r
		}
	}
	var best *Region
	bestD := math.MaxFloat64
	for i := range regions {
		r := &regions[i]
		if _, ok := cityRadius[r.Code]; ok {
			continue
		}
		if d := haversine(lat, lon, r.Lat, r.Lon); d < bestD {
			best, bestD = r, d
		}
	}
	for _, p := range extraPoints {
		if d := haversine(lat, lon, p.Lat, p.Lon); d < bestD {
			best, bestD = RegionByCode(p.Code), d
		}
	}
	if bestD > maxRegionKm {
		return nil
	}
	return best
}

// RegionByCode looks up a region by ISO code.
func RegionByCode(code string) *Region {
	for i := range regions {
		if regions[i].Code == code {
			return &regions[i]
		}
	}
	return nil
}

// Regions returns all known regions.
func Regions() []Region { return append([]Region(nil), regions...) }

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}
