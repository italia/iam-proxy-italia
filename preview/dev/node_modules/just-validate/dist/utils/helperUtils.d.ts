import { ClassListType, GroupFieldInterface, GroupFieldsInterface } from '../modules/interfaces';
export declare const isPromise: (val?: unknown) => boolean;
export declare const getNodeParents: (el: HTMLElement) => HTMLElement[];
export declare const getClosestParent: (groups: GroupFieldsInterface, parents: HTMLElement[]) => [string, GroupFieldInterface] | null;
export declare const getClassList: (classList?: ClassListType) => string[];
export declare const mapToObject: <S, T>(map: Map<S, T>) => {
    [key: string]: T;
};
export declare const isElement: (element: unknown) => boolean;
