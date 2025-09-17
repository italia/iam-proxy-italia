import axios from 'axios';
import express, { Request, Response, Router } from 'express';
import { Agent } from 'node:https';
const proxyRouter: Router = express.Router();

const agent = new Agent({
    rejectUnauthorized: false,
});

proxyRouter.post('/', async (req, res) => {
	const { headers, method, url, data } = req.body;
	try {
		const isBinaryRequest = /\.(png|jpe?g|gif|webp|bmp|tiff?|ico)(\?.*)?(#.*)?$/i.test(url);
		console.log("URL = ", url)
		const response = await axios({
			url: url,
			headers: headers,
			method: method,
			data: data,
			...(isBinaryRequest && { responseType: 'arraybuffer' }),
			maxRedirects: 0,
			httpsAgent: agent,
		});

		if (isBinaryRequest) {
			// forward all response headers
			for (const key in response.headers) {
				if (Object.prototype.hasOwnProperty.call(response.headers, key)) {
					const value = response.headers[key];
					if (value !== undefined) {
						res.setHeader(key, value as string);
					}
				}
			}
			return res.status(response.status).send(response.data);
		}

		// JSON or other text content
		return res.status(response.status).send({
			status: response.status,
			headers: response.headers,
			data: response.data,
		});
	}
	catch (err) {
		console.error("Error in proxy request: ", err);
		if (err.response && err.response.data) {
			console.error("Error data = ", err.response.data)
		}
		if (err.response && err.response.status == 302) {
			return res.status(200).send({ status: err.response.status, headers: err.response.headers, data: {} })
		}
		return res.status(err.response?.status ?? 104).send({ status: err.response?.status ?? 104, data: err.response?.data, headers: err.response?.headers });
	}
})

export {
	proxyRouter
}