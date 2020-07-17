#
# Generate the diagrams. Don't forget to run this after editing the sources in
# the 'uml' directory.
#
# Needs to be run from the 'docs/architecture/threat_model/' directory.
#

plantuml -o ../img -tsvg uml/*.plantuml

