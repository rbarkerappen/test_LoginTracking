#!/usr/bin/env python

from app import Country, app, db

db.create_all()

countries = [
	Country(name="United States of America", code="US"),
	Country(name="Canada", code="CA"),
	Country(name="Australia", code="AU"),
	Country(name="Egypt", code="EG"),
	Country(name="The Philippines", code="PH"),
]

for c in countries:
	db.session.add(c)

db.session.commit()

print "Database has been successfully setup."
