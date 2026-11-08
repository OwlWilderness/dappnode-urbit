"""Image-only explicit fresh-planet service; stock managed_service stays unchanged."""
from planet import PlanetImporter
from server import main

if __name__ == '__main__':
    raise SystemExit(main(engine_class=PlanetImporter))
