import { HttpException, HttpStatus } from '@nestjs/common';

export class EntityNotFoundException extends HttpException {
  constructor(entity: string, id: string) {
    super(`${entity} con ID ${id} non trovato`, HttpStatus.NOT_FOUND);
  }
}
