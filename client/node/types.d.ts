export class Message {
  constructor(degree: number | bigint);
  getDegree(): number;
  get(index: number): number;
  set(index: number, value: number): void;
  asTypedArray(): Float64Array;
}

export class Polynomial {
  constructor(degree: number | bigint, mod: number | bigint);
  getDegree(): number;
  getMod(): bigint;
  getIsNTT(): boolean;
  setIsNTT(value: boolean): void;
  get(index: number): bigint;
  set(index: number, value: number | bigint): void;
  asTypedArray(): BigUint64Array;
}

export class SecretKey {
  constructor();
  getPolyQ(): Polynomial;
  getPolyP(): Polynomial;
}

export class SwitchingKey {
  constructor();
  getPolyAModQ(): Polynomial;
  getPolyAModP(): Polynomial;
  getPolyBModQ(): Polynomial;
  getPolyBModP(): Polynomial;
}

export class MLWESwitchingKey {
  constructor(rank: number | bigint);
  getPolyAModQ(index: number): Polynomial;
  getPolyAModP(index: number): Polynomial;
  getPolyBModQ(index: number): Polynomial;
  getPolyBModP(index: number): Polynomial;
}

export class AutedModPackKeys {
  constructor(rank: number | bigint);
  getKey(i: number, j: number): SwitchingKey;
}

export class AutedModPackMLWEKeys {
  constructor(rank: number | bigint);
  getKey(i: number, j: number): MLWESwitchingKey;
}

export class Ciphertext {
  constructor(isExtended?: boolean);
  setIsNTT(value: boolean): void;
  getDegree(): number;
  getIsExtended(): boolean;
  getIsNTT(): boolean;
  getA(): Polynomial;
  getB(): Polynomial;
  getC(): Polynomial;
}

export class MLWECiphertext {
  constructor(rank: number | bigint);
  getA(index: number): Polynomial;
  getB(): Polynomial;
}

export class CachedQuery {
  constructor(rank: number | bigint);
  size(): number;
}

export class CachedKeys {
  constructor(rank: number | bigint);
  size(): number;
}

export class TopK {
  constructor(k: number);
  get(index: number): number;
  set(index: number, value: number): void;
  length(): number;
}

export class Client {
  constructor(logRank: number | bigint);
  genSecKey(secret: SecretKey): void;
  genRelinKey(result: SwitchingKey, secret: SecretKey): void;
  genAutedModPackKeys(result: AutedModPackKeys, secret: SecretKey): void;
  genInvAutedModPackKeys(result: AutedModPackMLWEKeys, secret: SecretKey): void;
  encryptQuery(
    result: MLWECiphertext,
    message: Message,
    secret: SecretKey,
    scale: number,
  ): void;
  encryptKey(
    result: MLWECiphertext,
    message: Message,
    secret: SecretKey,
    scale: number,
  ): void;
  encode(result: Polynomial, message: Message, scale: number): void;
  decode(result: Message, polynomial: Polynomial, scale: number): void;
  encryptPolynomial(
    result: Ciphertext,
    polynomial: Polynomial,
    secret: SecretKey,
  ): void;
  encryptMessage(
    result: Ciphertext,
    message: Message,
    secret: SecretKey,
    scale: number,
  ): void;
  decrypt(
    result: Message,
    ciphertext: Ciphertext,
    secret: SecretKey,
    scale: number,
  ): void;
  decryptScore(
    resultMessages: Message[],
    scores: Ciphertext[],
    secret: SecretKey,
    scale: number,
  ): void;
  topKScore(result: TopK, messages: Message[]): void;
  getRank(): number;
  getInvRank(): number;
}

export class Server {
  constructor(
    logRank: number | bigint,
    relinKey: SwitchingKey,
    autedKeys: AutedModPackKeys,
    autedMLWEKeys: AutedModPackMLWEKeys,
  );
  cacheQuery(cache: CachedQuery, query: MLWECiphertext): void;
  cacheKeys(cache: CachedKeys, keys: MLWECiphertext[]): void;
  innerProduct(
    result: Ciphertext,
    cachedQuery: CachedQuery,
    cachedKeys: CachedKeys,
  ): void;
}

export class HEVECClient {
  constructor(host: string, port: string);
  setupCollection(
    collection: string,
    dimension: number | bigint,
    metric: string,
    isQueryEncrypt?: boolean,
  ): bigint;
  dropCollection(collection: string): void;
  terminate(): void;
  insert(
    collection: string,
    database: ArrayLike<ArrayLike<number>>,
    payloads: string[],
  ): void;
  query(collection: string, queryVector: ArrayLike<number>): number[];
  queryAndTopK(result: TopK, collection: string, queryVector: ArrayLike<number>): void;
  queryAndTopKWithScores(
    collection: string,
    queryVector: ArrayLike<number>,
    k: number | bigint,
  ): [bigint, number][];
  retrieve(collection: string, index: number | bigint): string;
  retrievePIR(collection: string, index: number | bigint): string;
}

export interface MetricTypeMap {
  IP: number;
  L2: number;
  COSINE: number;
}

export interface HEVECBinding {
  Message: typeof Message;
  Polynomial: typeof Polynomial;
  SecretKey: typeof SecretKey;
  SwitchingKey: typeof SwitchingKey;
  MLWESwitchingKey: typeof MLWESwitchingKey;
  AutedModPackKeys: typeof AutedModPackKeys;
  AutedModPackMLWEKeys: typeof AutedModPackMLWEKeys;
  Ciphertext: typeof Ciphertext;
  MLWECiphertext: typeof MLWECiphertext;
  CachedQuery: typeof CachedQuery;
  CachedKeys: typeof CachedKeys;
  TopK: typeof TopK;
  Client: typeof Client;
  Server: typeof Server;
  HEVECClient: typeof HEVECClient;
  MetricType: MetricTypeMap;
  getTopKIndices(
    scores: ArrayLike<number>,
    k: number | bigint,
  ): bigint[];
}
