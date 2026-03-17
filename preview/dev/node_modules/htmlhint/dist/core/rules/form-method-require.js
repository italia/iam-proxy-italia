"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'form-method-require',
    description: 'The method attribute of a <form> element must be present with a valid value: "get", "post", or "dialog".',
    init(parser, reporter) {
        const onTagStart = (event) => {
            const tagName = event.tagName.toLowerCase();
            if (tagName === 'form') {
                const mapAttrs = parser.getMapAttrs(event.attrs);
                const col = event.col + tagName.length + 1;
                if (mapAttrs.method === undefined) {
                    reporter.warn('The method attribute must be present on <form> elements.', event.line, col, this, event.raw);
                }
                else {
                    const methodValue = mapAttrs.method.toLowerCase();
                    if (methodValue !== 'get' &&
                        methodValue !== 'post' &&
                        methodValue !== 'dialog') {
                        reporter.warn('The method attribute of <form> must have a valid value: "get", "post", or "dialog".', event.line, col, this, event.raw);
                    }
                }
            }
        };
        parser.addListener('tagstart', onTagStart);
    },
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZm9ybS1tZXRob2QtcmVxdWlyZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9jb3JlL3J1bGVzL2Zvcm0tbWV0aG9kLXJlcXVpcmUudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFHQSxrQkFBZTtJQUNiLEVBQUUsRUFBRSxxQkFBcUI7SUFDekIsV0FBVyxFQUNULDBHQUEwRztJQUM1RyxJQUFJLENBQUMsTUFBTSxFQUFFLFFBQVE7UUFDbkIsTUFBTSxVQUFVLEdBQWEsQ0FBQyxLQUFLLEVBQUUsRUFBRTtZQUNyQyxNQUFNLE9BQU8sR0FBRyxLQUFLLENBQUMsT0FBTyxDQUFDLFdBQVcsRUFBRSxDQUFBO1lBRTNDLElBQUksT0FBTyxLQUFLLE1BQU0sRUFBRSxDQUFDO2dCQUN2QixNQUFNLFFBQVEsR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtnQkFDaEQsTUFBTSxHQUFHLEdBQUcsS0FBSyxDQUFDLEdBQUcsR0FBRyxPQUFPLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQTtnQkFFMUMsSUFBSSxRQUFRLENBQUMsTUFBTSxLQUFLLFNBQVMsRUFBRSxDQUFDO29CQUNsQyxRQUFRLENBQUMsSUFBSSxDQUNYLDBEQUEwRCxFQUMxRCxLQUFLLENBQUMsSUFBSSxFQUNWLEdBQUcsRUFDSCxJQUFJLEVBQ0osS0FBSyxDQUFDLEdBQUcsQ0FDVixDQUFBO2dCQUNILENBQUM7cUJBQU0sQ0FBQztvQkFDTixNQUFNLFdBQVcsR0FBRyxRQUFRLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxDQUFBO29CQUNqRCxJQUNFLFdBQVcsS0FBSyxLQUFLO3dCQUNyQixXQUFXLEtBQUssTUFBTTt3QkFDdEIsV0FBVyxLQUFLLFFBQVEsRUFDeEIsQ0FBQzt3QkFDRCxRQUFRLENBQUMsSUFBSSxDQUNYLHFGQUFxRixFQUNyRixLQUFLLENBQUMsSUFBSSxFQUNWLEdBQUcsRUFDSCxJQUFJLEVBQ0osS0FBSyxDQUFDLEdBQUcsQ0FDVixDQUFBO29CQUNILENBQUM7Z0JBQ0gsQ0FBQztZQUNILENBQUM7UUFDSCxDQUFDLENBQUE7UUFFRCxNQUFNLENBQUMsV0FBVyxDQUFDLFVBQVUsRUFBRSxVQUFVLENBQUMsQ0FBQTtJQUM1QyxDQUFDO0NBQ00sQ0FBQSJ9