import JustValidate, { FieldSelectorType } from '../main';
export declare const clickBySelector: (selector: string) => Promise<void>;
export declare const getElem: (selector: string) => Element | null;
export declare const getAllElemsByKey: (testId: string, fieldSelector: FieldSelectorType, instance: JustValidate, parent?: Element) => NodeListOf<Element>;
export declare const getElemByKey: (testId: string, fieldSelector: FieldSelectorType, instance: JustValidate, parent?: Element) => Element | null;
export declare const changeTextBySelector: (selector: string, value: string) => Promise<void>;
export declare const selectBySelector: (selector: string, value: string) => Promise<void>;
export declare const fetch: (time?: number, func?: () => boolean) => Promise<boolean>;
export declare const generateFileContent: (size: number) => Array<string>;
