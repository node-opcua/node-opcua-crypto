
test-cov: coverage coveralls codeclimate

coverage:
	nyc mocha
	
coveralls: coverage
	npm install coveralls 
	cat ./coverage/lcov.info | node ./node_modules/coveralls/bin/coveralls.js --exclude tmp

# note a CODECLIMATE_REPO_TOKEN must be specified as an environment variable.
codeclimate: coverage
	npm install -g codeclimate-test-reporter
	codeclimate-test-reporter < ./coverage/lcov.info


