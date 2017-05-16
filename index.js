const ip = require('ip');

/**
 * DNS opcodes (let's call them request codes for consistency)
 * @type {object}
 */
const RequestCode = {
	'Query': 0,
	'IQuery': 1,
	'Status': 2,
	'Notify': 4,
	'Update': 5
};

for(const i in RequestCode) {
	if(RequestCode.hasOwnProperty(i)) {
		RequestCode[RequestCode[i]] = i;
	}
}

/**
 * Common DNS rcodes (let's call them response codes for consisteny)
 * @note There's 16 possible codes (4 bits) plus *a lot* codes (additional 8 bits) introduced by eDNS
 * @type {object}
 */
const ResponseCode = {
	'NOERROR': 0,
	'FORMERR': 1,
	'SSERVFAIL': 2,
	'NXDOMAIN': 3,
	'NOTIMP': 4,
	'REFUSED': 5,
	'YXDOMAIN': 6,
	'XRRSET': 7,
	'NOTAUTH': 8,
	'NOTZONE': 9
};

for(const i in ResponseCode) {
	if(ResponseCode.hasOwnProperty(i)) {
		ResponseCode[ResponseCode[i]] = i;
	}
}

/**
 * Supported DNS record classes
 * @type {object}
 */
const Class = {
	'IN': 1
};

for(const i in Class) {
	if(Class.hasOwnProperty(i)) {
		Class[Class[i]] = i;
	}
}

/**
 * Supported DNS record types
 * @type {object}
 */
const Type = {
	'A': 1,
	'NS': 2,
	'CNAME': 5,
	'SOA': 6,
	'PTR': 12,
	'MX': 15,
	'AAAA': 28,
	'SRV': 33,
//	'OPT': 41, // Pseudo-RR
	'ANY': 255
};

for(const i in Type) {
	if(Type.hasOwnProperty(i)) {
		Type[Type[i]] = i;
	}
}

/**
 * Helper function to concatenate array of DNS labels to domain name
 * @param labels {Buffer[]} array of DNS labels
 * @return {string} concatenated labels
 * FIXME: Is it actually right thing to do? Can labels contain dots?
 */
function labelsToString(labels) {
	return labels.join('.');
}

/**
 * Serializes packet header into buffer
 * @param packet {object} packet object
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} header end offset
 */
function serializeHeader(packet, buffer, cursor) {
	var bits = 0x0000;

	if(packet.response)           bits |= 0x8000;
	bits |= (packet.opcode & 0x0f) << 11;
	if(packet.authoritative)      bits |= 0x0400;
	if(packet.truncated)           bits |= 0x0200;
	if(packet.recursionDesired)   bits |= 0x0100;

	if(packet.recursionAvailable) bits |= 0x0080;
	bits |= (packet.zero & 0x0001) << 6;
	if(packet.authenticated) bits |= 0x0020;
	if(packet.checkingDisabled) bits |= 0x0010;

	bits |= packet.rcode & 0x0f;

	buffer.writeUInt16BE(packet.id, cursor);
	buffer.writeUInt16BE(bits, cursor + 2);
	buffer.writeUInt16BE('question' in packet ? packet.question.length : 0, cursor + 4);
	buffer.writeUInt16BE('answer' in packet ? packet.answer.length : 0, cursor + 6);
	buffer.writeUInt16BE('authority' in packet ? packet.authority.length : 0, cursor + 8);
	buffer.writeUInt16BE('additional' in packet ? packet.additional.length : 0, cursor + 10);

	return cursor + 12;
}

/**
 * Serializes DNS name (or array of DNS labels) into buffer
 * @param name {string|string[]|buffer[]} name to be serialized
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} name end offset
 */
function serializeName(name, buffer, cursor) {
	const labels = name instanceof Array ? name : name.split('.');
	for(let label of labels) {

		if(!label) {
			// skip empty labels... should fire error of sime kind?
			continue;
		}

		label = Buffer(label);

		const labelLength = label.length;

		if(labelLength > 63) {
			throw new Error('Label length over 63 bytes');
		}

		buffer.writeUInt8(labelLength, cursor);
		cursor++;
		label.copy(buffer, cursor);
		cursor += labelLength;
	}

	buffer.writeUInt8(0, cursor);

	return cursor + 1;
}

/**
 * Serializes DNS question into buffer
 * @param question {object} question descriptor
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} question end offset
 */
function serializeQuestion(question, buffer, cursor) {

	if(typeof question.name !== 'string') {
		throw new Error('Invalid RR name ' + question.name);
	}

	cursor = serializeName(question.name, buffer, cursor);

	if(Number.isInteger(question.type)) {
		buffer.writeUInt16BE(question.type, cursor);
	} else if(Type.hasOwnProperty(question.type) && Number.isInteger(Type[question.type])) {
		buffer.writeUInt16BE(Type[question.type], cursor);
	} else {
		throw new Error('Unknown record type ' + question.type);
	}

	if('class' in question) {
		if(Number.isInteger(question.class)) {
			buffer.writeUInt16BE(question.class, cursor + 2);
		} else if(Class.hasOwnProperty(question.class) && Number.isInteger(Class[question.class])) {
			buffer.writeUInt16BE(Class[question.class], cursor + 2);
		} else {
			throw new Error('Unknown record class ' + question.class);
		}
	} else {
		buffer.writeUInt16BE(Class.IN, cursor + 2);
	}

	return cursor + 4;
}

/**
 * Serializes DNS record into buffer
 * @param record {object} record descriptor
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} record end offset
 */
function serializeRecord(record, buffer, cursor) {
	cursor = serializeQuestion(record, buffer, cursor);

	const ttl = Number.isInteger(record.ttl) ? record.ttl : 300;

	buffer.writeUInt32BE(ttl, cursor);
	cursor += 6;

	const newCursor = serializeRecordData(record, buffer, cursor);
	buffer.writeUInt16BE(newCursor - cursor, cursor - 2);

	return newCursor;
}

/**
 * Serializes DNS record data into buffer
 * @param record {object} record descriptor
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} record data end offset
 */
function serializeRecordData(record, buffer, cursor) {
	const type = typeof record.type === 'string' ? record.type : Type[record.type];

	switch(type) {
		case 'A': {
			const ipBuf = ip.toBuffer(record.ip);
			if(ipBuf.length !== 4) {
				throw new Error('Invalid IPv4 address ' + record.ip);
			}
			ipBuf.copy(buffer, cursor);
			return cursor + 4;
		}
		case 'AAAA': {
			const ipBuf = ip.toBuffer(record.ip);
			if(ipBuf.length !== 16) {
				throw new Error('Invalid IPv6 address ' + record.ip);
			}
			ipBuf.copy(buffer, cursor);
			return cursor + 16;
		}
		case 'MX': {
			const priority = Number.isInteger(record.priority) ? record.priority : 0;
			buffer.writeUInt16BE(priority, cursor);
			cursor += 2;
		}
		// falls through
		case 'NS':
		case 'CNAME':
		case 'PTR':
			if(typeof record.target !== 'string') {
				throw new Error('Invalid target name ' + record.target);
			}
			return serializeName(record.target, buffer, cursor);
		case 'SOA': {
			const primary = record.primary;
			const mailbox = record.mailbox;

			if(typeof primary !== 'string') {
				throw new Error('Invalid primary server name ' + primary);
			}

			if(typeof mailbox !== 'string') {
				throw new Error('Invalid mailbox name ' + mailbox);
			}

			const serial = Number.isInteger(record.serial) ? record.serial : 1;
			const refresh = Number.isInteger(record.refresh) ? record.refresh : 86400;
			const retry = Number.isInteger(record.retry) ? record.retry : 300;
			const expire = Number.isInteger(record.expire) ? record.expire : 3600;
			const ttl = Number.isInteger(record.ttl) ? record.ttl : 3600;

			cursor = serializeName(primary, buffer, cursor);
			cursor = serializeName(mailbox, buffer, cursor);

			buffer.writeUInt32BE(serial, cursor);
			buffer.writeUInt32BE(refresh, cursor + 4);
			buffer.writeUInt32BE(retry, cursor + 8);
			buffer.writeUInt32BE(expire, cursor + 12);
			buffer.writeUInt32BE(ttl, cursor + 16);

			return cursor + 20;
		}
		case 'SRV': {
			const priority = Number.isInteger(record.priority) ? record.priority : 0;
			const weight = Number.isInteger(record.weight) ? record.weight : 0;

			if(typeof record.target !== 'string') {
				throw new Error('Invalid target name ' + record.target);
			}

			if(!Number.isInteger(record.port)) {
				throw new Error('Invalid port number ' + record.port);
			}

			buffer.writeUInt16BE(priority, cursor);
			buffer.writeUInt16BE(weight, cursor + 2);
			buffer.writeUInt16BE(record.port, cursor + 4);
			cursor = serializeName(record.target, buffer, cursor + 6);
			return cursor;
		}
		default:
			throw new Error('Unsupported RR type: ' + type);
	}
}

/**
 * Serializes OPT record into buffer
 * @param edns {object} edns descriptor
 * @param buffer {Buffer} output buffer
 * @param cursor {number} buffer offset
 * @returns {number} edns record end offset
 */
function serializeEdns(edns, buffer, cursor) {

	buffer.writeUInt8(0, cursor); // Empty record name
	buffer.writeUInt16BE(41, cursor); // OPT record type
	buffer.writeUInt16BE(edns.maxSize, cursor + 2); // maximum recipient packet size in place of record class

	var ttl = 0;

	const rcode = Number.isInteger(edns.rcode) ? edns.rcode & 0xff : 0;
	ttl |= rcode << 24;

	const version = Number.isInteger(edns.version) ? edns.version & 0xff : 0;
	ttl |= version << 16;

	if(edns.dnssec) ttl |= 0x00008000;

	const zero = Number.isInteger(edns.zero) ? edns.zero & 0x7fff : 0;
	ttl |= zero;

	buffer.writeUInt32BE(ttl, cursor + 4);
	buffer.writeUInt16BE(0, cursor + 8); // length of rdata - always 0 as eDNS options are not supported

	return cursor + 11;
}

/**
 * Serializes packet object into buffer
 * @param {object} packet to be serialized
 * @returns {Buffer} serialized packet ready to be sent
 */
function serialize(packet) {
	const buffer = new Buffer(512);
	var cursor = serializeHeader(packet, buffer, 0);

	if('question' in packet) {
		for(const question of packet.question) {
			cursor = serializeQuestion(question, buffer, cursor);
		}
	}

	if('answer' in packet) {
		for(const answer of packet.answer) {
			cursor = serializeRecord(answer, buffer, cursor);
		}
	}

	if('authority' in packet) {
		for(const authority of packet.authority) {
			cursor = serializeRecord(authority, buffer, cursor);
		}
	}

	if('additional' in packet) {
		for(const additional of packet.additional) {
			cursor = serializeRecord(additional, buffer, cursor);
		}
	}

	if('edns' in packet) {
		cursor = serializeEdns(packet.edns, buffer, cursor);
	}

	return buffer.slice(0, cursor);
}

/**
 * Parses DNS packet header
 * @param buffer {Buffer} input buffer
 * @param cursor {number} start offset
 * @param packet {object} object to be filled with header data
 * @returns {number} end offset
 */
function parseHeader(buffer, cursor, packet) {
	packet.id = buffer.readUInt16BE(cursor);
	var bits = buffer.readUInt16BE(cursor + 2);

	packet.response = Boolean(bits & 0x8000); // 0 - request; 1 - response
	packet.opcode = (bits & 0x7800) >> 11; // copied from request to response
	packet.authoritative = Boolean(bits & 0x0400); // valid in responses only
	packet.truncated = Boolean(bits & 0x0200);
	packet.recursionDesired = Boolean(bits & 0x0100); // copied from request to response on successful recursive query

	packet.recursionAvailable = Boolean(bits & 0x0080); // valid in responses only
	packet.zero = (bits & 0x0040) >> 6; // must be zero
	packet.authenticated = Boolean(bits & 0x0020); // data in request or response is authenticated according to some policies
	packet.checkingDisabled = Boolean(bits & 0x0010); // valid in requests only
	packet.rcode = bits & 0x000f; // valid in responses only

	packet.questionCount = buffer.readUInt16BE(cursor + 4);
	packet.answerCount = buffer.readUInt16BE(cursor + 6);
	packet.authorityCount = buffer.readUInt16BE(cursor + 8);
	packet.additionalCount = buffer.readUInt16BE(cursor + 10);

	cursor += 12;

	return cursor;
}

/**
 * Parses DNS name (array of labels)
 * @param buffer {Buffer} input buffer
 * @note buffer must represent entire packet starting at offset 0 to support label pointers
 * @param cursor {number} start offset
 * @param labels {object} array to be filled with labels
 * @returns {number} end offset
 */
function parseName(buffer, cursor, labels) {

	var labelLength;

	function followPointer(cursor) {

		while((labelLength = buffer.readUInt8(cursor)) > 0) {

			if((labelLength & 0xC0) == 0xC0) { // 11xxxxxxxx
				// label pointer
				cursor = ((labelLength & 0x3f) << 8) | buffer.readUInt8(cursor + 1); // last 14 bits
				continue;
			}

			if(labelLength > 63) {
				throw new Error('Label lengths above 63 are not supported');
			}

			cursor++;
			const label = buffer.slice(cursor, cursor + labelLength);
			labels.push(label);
			cursor += labelLength;
		}
	}

	while((labelLength = buffer.readUInt8(cursor)) > 0) {

		if((labelLength & 0xc0) === 0xc0) { // label pointer
			followPointer(cursor);
			return cursor + 2;
		}

		if((labelLength & 0xc0) === 0x40) { // extended label type
			throw new Error('Unsupported extended label type: 0x' + (labelLength & 0x3f).toString(16));
		}

		if(labelLength > 63) {
			// TODO: support pointers and other kind of magic
			throw new Error('Label lengths above 63 are not supported');
		}

		cursor++;
		const label = buffer.slice(cursor, cursor + labelLength);
		labels.push(label);
		cursor += labelLength;
	}

	return cursor + 1;
}

/**
 * Parses DNS question
 * @param buffer {Buffer} input buffer
 * @param cursor {number} start offset
 * @param question {object} object to be filled with question data
 * @returns {number} end offset
 */
function parseQuestion(buffer, cursor, question) {

	const labels = [];
	cursor = parseName(buffer, cursor, labels);

	const type = buffer.readUInt16BE(cursor);
	const clazz = buffer.readUInt16BE(cursor + 2);

	// RR-s with unknown type or class are ignored (skipped)
	if(!(type in Type) || !(clazz in Class)) {
		return cursor + 4;
	}

	question.name = labelsToString(labels);
	question.type = Type[type];
	question.class = Class[clazz];

	return cursor + 4;
}

/**
 * Parses DNS record
 * @param buffer {Buffer} input buffer
 * @param cursor {number} start offset
 * @param record {object} object to be filled with record data
 * @returns {number} end offset
 */
function parseRecord(buffer, cursor, record) {

	const labels = [];
	cursor = parseName(buffer, cursor, labels);

	const type = buffer.readUInt16BE(cursor);
	const clazz = buffer.readUInt16BE(cursor + 2);
	const ttl = buffer.readUInt32BE(cursor + 4);
	const rdlen = buffer.readUInt16BE(cursor + 8);

	record.name = labelsToString(labels);
	record.type = Type.hasOwnProperty(type) ? Type[type] : type;

	if(type === 41) { // OPT pseudorecord for eDNS
		record.type = 'OPT';
		record.maxSize = clazz;
		record.rcode = (ttl & 0xff000000) >> 8; // MSB of TTL
		record.version = (ttl & 0x00ff0000);
		record.dnssec = Boolean(ttl & 0x00008000);
		record.zero = ttl & 0x00007fff;
		// TODO: support eDNS options
		return cursor + 10 + rdlen;
	}

	// RR-s with unknown type or class are ignored (skipped)
	if(!(type in Type) || !(clazz in Class)) {
		return cursor + 10 + rdlen;
	}

	record.class = Class.hasOwnProperty(clazz) ? Class[clazz] : clazz;
	record.ttl = ttl;
	parseRecordData(buffer, cursor + 10, record);

	return cursor + 10 + rdlen;
}

/**
 * Parses DNS record data
 * @param buffer {Buffer} input buffer
 * @param cursor {number} start offset
 * @param record {object} object to be filled with record data
 * @returns {number} end offset
 */
function parseRecordData(buffer, cursor, record) {
	switch(record.type) {
		case 'A':
			record.ip = ip.toString(buffer, cursor, 4);
			return cursor + 4;
		case 'AAAA':
			record.ip = ip.toString(buffer, cursor, 16);
			return cursor + 16;
		case 'MX':
			record.priority = buffer.readUInt16BE(cursor);
			cursor += 2;
		// falls through
		case 'NS':
		case 'CNAME':
		case 'PTR': {
			const labels = [];
			cursor = parseName(buffer, cursor, labels);
			record.host = labelsToString(labels);
			return cursor;
		}
		case 'SOA': {
			let labels = [];
			cursor = parseName(buffer, cursor, labels);
			record.primary = labelsToString(labels);
			labels = [];
			cursor = parseName(buffer, cursor, labels);
			record.mailbox = labelsToString(labels);
			record.serial = buffer.readUInt32BE(cursor);
			record.refresh = buffer.readUInt32BE(cursor + 4);
			record.retry = buffer.readUInt32BE(cursor + 8);
			record.expire = buffer.readUInt32BE(cursor + 12);
			record.ttl = buffer.readUInt32BE(cursor + 16);
			return cursor + 20;
		}
		case 'SRV': {
			record.priority = buffer.readUInt16BE(cursor);
			record.weight = buffer.readUInt16BE(cursor + 2);
			record.port = buffer.readUInt16BE(cursor + 4);
			const labels = [];
			cursor = parseName(buffer, cursor + 6, labels);
			record.target = labelsToString(labels);
			return cursor;
		}
		default:
			throw new Error('Unsupported RR type: ' + type);
	}
}

/**
 * Parses buffer to packet object
 * @param buffer {Buffer} input buffer
 * @return {object} packet object
 */
function parse(buffer) {

	const packet = {};

	var cursor = parseHeader(buffer, 0, packet);

	packet.question = [];
	for(let i = 0; i < packet.questionCount && cursor; i++) {
		const question = {};
		cursor = parseQuestion(buffer, cursor, question);
		packet.question.push(question);
	}

	packet.answer = [];
	for(let i = 0; i < packet.answerCount && cursor; i++) {
		const answer = {};
		cursor = parseRecord(buffer, cursor, answer);
		if(answer.type === 'OPT') {
			throw new Error('Found OPT record in answer section');
		}
		packet.answer.push(answer);
	}

	packet.authority = [];
	for(let i = 0; i < packet.authorityCount && cursor; i++) {
		const authority = {};
		cursor = parseRecord(buffer, cursor, authority);
		if(authority.type === 'OPT') {
			throw new Error('Found OPT record in authority section');
		}
		packet.authority.push(authority);
	}

	packet.additional = [];
	for(let i = 0; i < packet.additionalCount && cursor; i++) {
		const additional = {};
		cursor = parseRecord(buffer, cursor, additional);
		if(additional.type === 'OPT') {
			if('edns' in packet) {
				throw new Error('Found duplicate OPT record');
			}

			if(additional.name !== '') {
				throw new Error('Invalid OPT record name');
			}

			delete additional.type;
			delete additional.name;
			packet.edns = additional;
		} else {
			packet.additional.push(additional);
		}
	}

	delete packet.questionCount;
	delete packet.answerCount;
	delete packet.authorityCount;
	delete packet.additionalCount;
	return packet;
}

/**
 * Clones packet
 * @param packet {object} packet to be cloned
 * @return {object} cloned packet
 * TODO: proper clone
 */
function clone(packet) {
	return JSON.parse(JSON.stringify(packet));
}

/**
 * Module exports
 */
module.exports = {
	Type,
	Class,
	RequestCode,
	ResponseCode,
	serialize,
	parse,
	clone
};
