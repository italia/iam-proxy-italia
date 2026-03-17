"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    id: 'link-rel-canonical-require',
    description: '<link rel="canonical"> with non-blank href must be present in <head> tag.',
    init(parser, reporter) {
        let headSeen = false;
        let linkCanonicalSeen = false;
        let linkCanonicalHref = '';
        let headEvent = null;
        const onTagStart = (event) => {
            const tagName = event.tagName.toLowerCase();
            if (tagName === 'head') {
                headSeen = true;
                headEvent = event;
            }
            else if (tagName === 'link') {
                const mapAttrs = parser.getMapAttrs(event.attrs);
                if (mapAttrs['rel'] && mapAttrs['rel'].toLowerCase() === 'canonical') {
                    linkCanonicalSeen = true;
                    linkCanonicalHref = mapAttrs['href'] || '';
                }
            }
        };
        parser.addListener('tagstart', onTagStart);
        parser.addListener('end', () => {
            if (headSeen && headEvent) {
                if (!linkCanonicalSeen) {
                    reporter.error('<link rel="canonical"> must be present in <head> tag.', headEvent.line, headEvent.col, this, headEvent.raw);
                }
                else if (linkCanonicalHref.trim() === '') {
                    reporter.error('<link rel="canonical"> href attribute must not be empty.', headEvent.line, headEvent.col, this, headEvent.raw);
                }
            }
        });
    },
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibGluay1yZWwtY2Fub25pY2FsLXJlcXVpcmUuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvY29yZS9ydWxlcy9saW5rLXJlbC1jYW5vbmljYWwtcmVxdWlyZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUdBLGtCQUFlO0lBQ2IsRUFBRSxFQUFFLDRCQUE0QjtJQUNoQyxXQUFXLEVBQ1QsMkVBQTJFO0lBQzdFLElBQUksQ0FBQyxNQUFNLEVBQUUsUUFBUTtRQUNuQixJQUFJLFFBQVEsR0FBRyxLQUFLLENBQUE7UUFDcEIsSUFBSSxpQkFBaUIsR0FBRyxLQUFLLENBQUE7UUFDN0IsSUFBSSxpQkFBaUIsR0FBRyxFQUFFLENBQUE7UUFDMUIsSUFBSSxTQUFTLEdBQWlCLElBQUksQ0FBQTtRQUVsQyxNQUFNLFVBQVUsR0FBYSxDQUFDLEtBQUssRUFBRSxFQUFFO1lBQ3JDLE1BQU0sT0FBTyxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUMsV0FBVyxFQUFFLENBQUE7WUFDM0MsSUFBSSxPQUFPLEtBQUssTUFBTSxFQUFFLENBQUM7Z0JBQ3ZCLFFBQVEsR0FBRyxJQUFJLENBQUE7Z0JBQ2YsU0FBUyxHQUFHLEtBQUssQ0FBQTtZQUNuQixDQUFDO2lCQUFNLElBQUksT0FBTyxLQUFLLE1BQU0sRUFBRSxDQUFDO2dCQUM5QixNQUFNLFFBQVEsR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtnQkFDaEQsSUFBSSxRQUFRLENBQUMsS0FBSyxDQUFDLElBQUksUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLFdBQVcsRUFBRSxLQUFLLFdBQVcsRUFBRSxDQUFDO29CQUNyRSxpQkFBaUIsR0FBRyxJQUFJLENBQUE7b0JBQ3hCLGlCQUFpQixHQUFHLFFBQVEsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLENBQUE7Z0JBQzVDLENBQUM7WUFDSCxDQUFDO1FBQ0gsQ0FBQyxDQUFBO1FBRUQsTUFBTSxDQUFDLFdBQVcsQ0FBQyxVQUFVLEVBQUUsVUFBVSxDQUFDLENBQUE7UUFDMUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxLQUFLLEVBQUUsR0FBRyxFQUFFO1lBQzdCLElBQUksUUFBUSxJQUFJLFNBQVMsRUFBRSxDQUFDO2dCQUMxQixJQUFJLENBQUMsaUJBQWlCLEVBQUUsQ0FBQztvQkFDdkIsUUFBUSxDQUFDLEtBQUssQ0FDWix1REFBdUQsRUFDdkQsU0FBUyxDQUFDLElBQUksRUFDZCxTQUFTLENBQUMsR0FBRyxFQUNiLElBQUksRUFDSixTQUFTLENBQUMsR0FBRyxDQUNkLENBQUE7Z0JBQ0gsQ0FBQztxQkFBTSxJQUFJLGlCQUFpQixDQUFDLElBQUksRUFBRSxLQUFLLEVBQUUsRUFBRSxDQUFDO29CQUMzQyxRQUFRLENBQUMsS0FBSyxDQUNaLDBEQUEwRCxFQUMxRCxTQUFTLENBQUMsSUFBSSxFQUNkLFNBQVMsQ0FBQyxHQUFHLEVBQ2IsSUFBSSxFQUNKLFNBQVMsQ0FBQyxHQUFHLENBQ2QsQ0FBQTtnQkFDSCxDQUFDO1lBQ0gsQ0FBQztRQUNILENBQUMsQ0FBQyxDQUFBO0lBQ0osQ0FBQztDQUNNLENBQUEifQ==