const owasp = {};

owasp.configs = {
	allowPassphrases: true,
	maxLength: 128,
	minLength: 10,
	minPhraseLength: 20,
	minOptionalTestsToPass: 4,
};

owasp.config = (params) => {
	for (const prop in params) {
		if (
			Object.prototype.hasOwnProperty.call(params, prop) &&
			Object.prototype.hasOwnProperty.call(owasp.configs, prop)
		) {
			owasp.configs[prop] = params[prop];
		}
	}
};

owasp.tests = {
	required: [
		(password) => {
			if (password.length < owasp.configs.minLength) {
				return `The password must be at least ${owasp.configs.minLength} characters long.`;
			}
		},
		(password) => {
			if (password.length > owasp.configs.maxLength) {
				return `The password must be fewer than ${owasp.configs.maxLength} characters.`;
			}
		},
		(password) => {
			if (/(.)\1{2,}/.test(password)) {
				return 'The password may not contain sequences of three or more repeated characters.';
			}
		},
	],
	optional: [
		(password) => {
			if (!/[a-z]/.test(password)) {
				return 'The password must contain at least one lowercase letter.';
			}
		},
		(password) => {
			if (!/[A-Z]/.test(password)) {
				return 'The password must contain at least one uppercase letter.';
			}
		},
		(password) => {
			if (!/[0-9]/.test(password)) {
				return 'The password must contain at least one number.';
			}
		},
		(password) => {
			if (!/[^A-Za-z0-9]/.test(password)) {
				return 'The password must contain at least one special character.';
			}
		},
	],
};

owasp.test = (password) => {
	const result = {
		errors: [],
		failedTests: [],
		passedTests: [],
		requiredTestErrors: [],
		optionalTestErrors: [],
		isPassphrase: false,
		strong: true,
		optionalTestsPassed: 0,
	};

	let i = 0;
	for (const test of owasp.tests.required) {
		const err = test(password);
		if (typeof err === 'string') {
			result.strong = false;
			result.errors.push(err);
			result.requiredTestErrors.push(err);
			result.failedTests.push(i);
		} else {
			result.passedTests.push(i);
		}
		i++;
	}
	if (
		owasp.configs.allowPassphrases === true &&
		password.length >= owasp.configs.minPhraseLength
	) {
		result.isPassphrase = true;
	}

	if (!result.isPassphrase) {
		let j = owasp.tests.required.length;
		for (const test of owasp.tests.optional) {
			const err = test(password);
			if (typeof err === 'string') {
				result.errors.push(err);
				result.optionalTestErrors.push(err);
				result.failedTests.push(j);
			} else {
				result.optionalTestsPassed++;
				result.passedTests.push(j);
			}
			j++;
		}
	}

	if (
		!result.isPassphrase &&
		result.optionalTestsPassed < owasp.configs.minOptionalTestsToPass
	) {
		result.strong = false;
	}

	return result;
};

export default owasp;
