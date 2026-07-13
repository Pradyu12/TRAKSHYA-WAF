package api

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net/http"

	"github.com/kalki-waf/kalki-api/pkg/models"
)

var countryNames = map[string]string{
	"US": "United States", "CN": "China", "RU": "Russia", "BR": "Brazil",
	"IN": "India", "GB": "United Kingdom", "DE": "Germany", "FR": "France",
	"JP": "Japan", "KR": "South Korea", "SG": "Singapore", "NL": "Netherlands",
	"AU": "Australia", "CA": "Canada", "IT": "Italy", "ES": "Spain",
	"SE": "Sweden", "NO": "Norway", "FI": "Finland", "DK": "Denmark",
	"PL": "Poland", "UA": "Ukraine", "IL": "Israel", "AE": "UAE",
	"ZA": "South Africa", "NG": "Nigeria", "EG": "Egypt", "AR": "Argentina",
	"MX": "Mexico", "CL": "Chile", "CO": "Colombia", "PE": "Peru",
	"TH": "Thailand", "VN": "Vietnam", "ID": "Indonesia", "PH": "Philippines",
	"MY": "Malaysia", "NZ": "New Zealand", "TW": "Taiwan", "HK": "Hong Kong",
	"CH": "Switzerland", "AT": "Austria", "BE": "Belgium", "IE": "Ireland",
	"PT": "Portugal", "GR": "Greece", "CZ": "Czech Republic", "HU": "Hungary",
	"RO": "Romania", "BG": "Bulgaria", "TR": "Turkey", "IR": "Iran",
	"PK": "Pakistan", "BD": "Bangladesh", "KE": "Kenya", "TZ": "Tanzania",
	"VE": "Venezuela", "SA": "Saudi Arabia",
}

func ipToCoords(ip string) (lat, lon float64) {
	h := sha256.Sum256([]byte(ip))
	latSeed := float64(binary.BigEndian.Uint32(h[0:4]))
	lonSeed := float64(binary.BigEndian.Uint32(h[4:8]))
	lat = (latSeed/float64(math.MaxUint32))*180.0 - 90.0
	lon = (lonSeed/float64(math.MaxUint32))*360.0 - 180.0
	if lat < -85 { lat = -85 }
	if lat > 85 { lat = 85 }
	return
}

func ipToCountryCode(ip string) string {
	h := sha256.Sum256([]byte(ip + "_country"))
	idx := binary.BigEndian.Uint32(h[0:4]) % uint32(len(countryNames))
	i := 0
	for code := range countryNames {
		if uint32(i) == idx {
			return code
		}
		i++
	}
	return "US"
}

func (s *Server) getGeoData(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetGeoData()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to get geo data")
		return
	}

	enriched := make([]models.GeoLocation, 0, len(stats.Locations))
	countrySet := make(map[string]bool)
	for _, loc := range stats.Locations {
		lat, lon := ipToCoords(loc.IP)
		code := ipToCountryCode(loc.IP)
		name := countryNames[code]
		loc.Latitude = math.Round(lat*100) / 100
		loc.Longitude = math.Round(lon*100) / 100
		loc.CountryCode = code
		loc.CountryName = name
		enriched = append(enriched, loc)
		countrySet[code] = true
	}
	stats.Locations = enriched
	stats.TotalCountries = len(countrySet)

	s.json(w, http.StatusOK, stats)
}
