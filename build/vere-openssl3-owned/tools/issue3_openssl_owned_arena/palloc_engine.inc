/* Generated from SHA256 7e6ac278d3082052d049f21b2a4b23ebb9c749ecfeaa4a33c9d7680dfac00d57; regenerate with overlay.py. No GC/checkpoint/pack code included. */
static void
_init_once(void)
{
  u3a_hunk_dose *hun_u;
  c3_s mun_w = 0;

  for (c3_g bit_g = 0; bit_g < u3a_crag_no; bit_g++ ) {
    hun_u = &(u3a_Hunk[bit_g]);
    hun_u->log_s = bit_g + u3a_min_log;
    hun_u->len_s = 1U << hun_u->log_s;
    hun_u->tot_s = 1U << (u3a_page - hun_u->log_s);
    hun_u->map_s = (hun_u->tot_s + 31) >> 5;
    hun_u->siz_s = c3_wiseof(u3a_crag) + hun_u->map_s - 1;

    //  metacircular base case
    //
    //    trivially deducible from exhaustive enumeration
    //
    if ( hun_u->len_s <= (hun_u->siz_s << 1) ) {
      hun_u->hun_s = 1U + ((hun_u->siz_s - 1) >> hun_u->log_s);
    }
    else {
      hun_u->hun_s = 0;
    }

    hun_u->ful_s = hun_u->tot_s - hun_u->hun_s;
    mun_w = c3_max(mun_w, hun_u->hun_s);
  }

  u3_assert( 32 > mun_w );
}

static __inline__ c3_w
_abs_dif(c3_w a_w, c3_w b_w)
{
  // c3_ds dif_ds = a_w - b_w;
  // c3_d  mas_d  = dif_ds >> 63;
  // return (dif_ds + mas_d) ^ mas_d;
  return (a_w > b_w ) ? a_w - b_w : b_w - a_w;
}

static u3_post
_alloc_pages(c3_w siz_w)  // num pages
{
  u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
  u3a_dell*      fre_u = u3tn(u3a_dell, HEAP.fre_p);
  u3a_dell*      del_u = NULL;
  c3_w           pag_w = 0;

  while ( fre_u ) {
    //  XX sanity

    if ( fre_u->siz_w < siz_w ) {
      fre_u = u3tn(u3a_dell, fre_u->nex_p);
      continue;
    }
    else if ( fre_u->siz_w == siz_w ) {
      pag_w = fre_u->pag_w;

      if ( fre_u->nex_p ) {
        u3to(u3a_dell, fre_u->nex_p)->pre_p = fre_u->pre_p;
      }
      else {
        HEAP.erf_p = fre_u->pre_p;
      }

      if ( fre_u->pre_p ) {
        u3to(u3a_dell, fre_u->pre_p)->nex_p = fre_u->nex_p;
      }
      else {
        HEAP.fre_p = fre_u->nex_p;
      }

      del_u = fre_u;
    }
    else {
      pag_w = fre_u->pag_w;
      fre_u->pag_w += siz_w;
      fre_u->siz_w -= siz_w;
    }
    break;
  }

  u3_post pag_p;

  if ( pag_w ) {
    //  XX groace
    //
    pag_w -= HEAP.off_ws * (siz_w - 1);
    pag_p  = page_to_post(pag_w);

#ifdef SANITY
    assert( pag_w < HEAP.len_w );

    //  XX sanity
    assert( u3a_free_pg == dir_u[pag_w] );
    for ( c3_w i_w = 1; i_w < siz_w; i_w++ ) {
      assert( u3a_free_pg == dir_u[pag_w + (HEAP.dir_ws * (c3_ws)i_w)] );
    }
#endif
  }
  else {
    pag_p = _extend_heap(siz_w);
    if ( !pag_p ) return 0;
    pag_w = post_to_page(pag_p);
    dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);

#ifdef SANITY
    assert( pag_w < HEAP.len_w );
    assert( (pag_w + ((HEAP.off_ws + 1) * siz_w) - HEAP.off_ws) == HEAP.len_w );
#endif
  }

  dir_u[pag_w] = u3a_head_pg;

  for ( c3_w i_w = 1; i_w < siz_w; i_w++ ) {
    dir_u[pag_w + (HEAP.dir_ws * (c3_ws)i_w)] = u3a_rest_pg;
  }

  //  XX junk

  ASAN_UNPOISON_MEMORY_REGION(u3a_into(pag_p), siz_w << (u3a_page + 2));

  if ( del_u ) {
    if ( !HEAP.cac_p ) {
      HEAP.cac_p = u3of(u3a_dell, del_u);
    }
    else {
      _ifree(u3of(u3a_dell, del_u));
    }
  }

#ifdef SANITY
  assert( HEAP.len_w == post_to_page(owner.hat_p + HEAP.off_ws) );
  assert( dir_u[HEAP.len_w - 1] );
#endif

  owner_charge_pages(siz_w);
  return pag_p;
}

static u3_post
_make_chunks(c3_g bit_g)  // 0-9, inclusive
{
  const u3a_hunk_dose *hun_u = &(u3a_Hunk[bit_g]);
  u3a_crag      *pag_u;
  u3_post hun_p, pag_p = _alloc_pages(1);
  c3_w    pag_w;
  if ( !pag_p ) return 0;
  pag_w = post_to_page(pag_p);

  ASAN_POISON_MEMORY_REGION(u3a_into(pag_p), 1U << (u3a_page + 2));

  if ( hun_u->hun_s ) {
    hun_p = pag_p;
    ASAN_UNPOISON_MEMORY_REGION(u3a_into(pag_p), (c3_z)hun_u->hun_s << (hun_u->log_s + 2));
  }
  else {
    hun_p = _imalloc(hun_u->siz_s);
    if ( !hun_p ) { _ifree(pag_p); return 0; }
  }

  pag_u = u3to(u3a_crag, hun_p);
  pag_u->pag_w = pag_w;
  pag_u->log_s = hun_u->log_s;
  pag_u->fre_s = hun_u->ful_s;

  //  initialize bitmap (ones, all free)
  //
  if ( hun_u->tot_s < 32 ) {
    pag_u->map_w[0] = (1U << hun_u->tot_s) - 1;
  }
  else {
    memset(pag_u->map_w, 0xff, (c3_z)hun_u->map_s << 2);
  }

  //  reserve chunks stolen for pginfo
  //  NB: max [hun_s] guarded by assertion in _init_once()
  //
  pag_u->map_w[0] &= ~0U << hun_u->hun_s;

  {
    u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
    dir_u[pag_w] = hun_p;
  }

  pag_u->nex_p = HEAP.wee_p[bit_g];
  HEAP.wee_p[bit_g] = hun_p;

  return hun_p;
}

static u3_post
_alloc_words(c3_w len_w)  //  4-2.048, inclusive
{
  c3_g      bit_g = (c3_g)c3_bits_word(len_w - 1) - u3a_min_log;  // 0-9, inclusive
  const u3a_hunk_dose *hun_u = &(u3a_Hunk[bit_g]);
  u3a_crag *pag_u;
  c3_w     *map_w;
  c3_g      pos_g;

  if ( !HEAP.wee_p[bit_g] ) {
    u3_post new_p = _make_chunks(bit_g);
    if ( !new_p ) return 0;
    pag_u = u3to(u3a_crag, new_p);
  }
  else {
    pag_u = u3to(u3a_crag, HEAP.wee_p[bit_g]);
    //  XX sanity

    if ( 1 == pag_u->fre_s ) {
      HEAP.wee_p[bit_g] = pag_u->nex_p;
      pag_u->nex_p = 0;
    }
  }

  pag_u->fre_s--;
  map_w = pag_u->map_w;
  while ( !*map_w ) { map_w++; }

  pos_g   = c3_tz_w(*map_w);
  *map_w &= ~(1U << pos_g);

  {
    u3_post out_p, bas_p = page_to_post(pag_u->pag_w);
    c3_w    off_w = (map_w - pag_u->map_w) << 5;

    out_p = bas_p + ((off_w + pos_g) << pag_u->log_s);
    ASAN_UNPOISON_MEMORY_REGION(u3a_into(out_p), hun_u->len_s << 2);
    //  XX poison suffix

    return out_p;
  }
}

static u3_post
_imalloc(c3_w len_w)
{
  if ( len_w > (1U << (u3a_page - 1)) ) {
    len_w  += (1U << u3a_page) - 1;
    len_w >>= u3a_page;
    //  XX poison suffix
    return _alloc_pages(len_w);
  }

  return _alloc_words(c3_max(len_w, u3a_minimum));
}

static inline c3_w
_pages_size(c3_w pag_w)
{
  u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
  c3_w           siz_w = 1;

  //  head-page 0 in a south road can only have a size of 1
  //
  if ( pag_w || !HEAP.off_ws ) {
    while( dir_u[pag_w + (HEAP.dir_ws * (c3_ws)siz_w)] == u3a_rest_pg ) {
      siz_w++;
    }
  }

  return siz_w;
}

static c3_w
_free_pages(u3_post som_p, c3_w pag_w, u3_post dir_p)
{
  u3a_dell *cac_u, *fre_u, *del_u = NULL;
  c3_w      nex_w,  siz_w = 1;
  u3_post   fre_p;

  if ( u3a_free_pg == dir_p ) {
    fprintf(stderr, "\033[31m"
                    "palloc: double free page som_p=0x%x pag_w=%u\r\n"
                    "\033[0m",
                    som_p, pag_w);
    u3_assert(!"loom: corrupt"); return 0;
  }

  if ( u3a_head_pg != dir_p ) {
    fprintf(stderr, "\033[31m"
                    "palloc: wrong page som_p=0x%x dir_p=0x%x\r\n"
                    "\033[0m",
                    som_p, dir_p);
    u3_assert(!"loom: corrupt"); return 0;
  }

  if ( som_p & ((1U << u3a_page) - 1) ) {
    fprintf(stderr, "\033[31m"
                    "palloc: bad page alignment som_p=0x%x\r\n"
                    "\033[0m",
                    som_p);
    u3_assert(!"loom: corrupt"); return 0;
  }

  {
    u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);

    dir_u[pag_w] = u3a_free_pg;

    //  head-page 0 in a south road can only have a size of 1
    //
    if ( pag_w || !HEAP.off_ws ) {
      while( dir_u[pag_w + (HEAP.dir_ws * (c3_ws)siz_w)] == u3a_rest_pg ) {
        dir_u[pag_w + (HEAP.dir_ws * (c3_ws)siz_w)] = u3a_free_pg;
        siz_w++;
      }
    }
  }

  owner_release_pages(siz_w);

  //  XX groace
  //
  if ( HEAP.off_ws ) {
    nex_w = pag_w + 1;
    pag_w = nex_w - siz_w;
  }
  else {
    nex_w = pag_w + siz_w;
  }

#ifdef SANITY
  assert( pag_w < HEAP.len_w );
  assert( HEAP.len_w == post_to_page(owner.hat_p + HEAP.off_ws) );
#endif

  if ( nex_w == HEAP.len_w ) {
    u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
    c3_w           wiz_w = siz_w;

    // check if prior pages are already free
    //
    if ( !dir_u[HEAP.len_w - (siz_w + 1)] ) {
      assert( HEAP.erf_p );
      fre_u = u3to(u3a_dell, HEAP.erf_p);
      assert( (fre_u->pag_w + fre_u->siz_w) == pag_w );

      if ( fre_u->pre_p ) {
        HEAP.erf_p = fre_u->pre_p;
        u3to(u3a_dell, fre_u->pre_p)->nex_p = 0;
      }
      else {
        HEAP.fre_p = HEAP.erf_p = 0;
      }

      pag_w  = fre_u->pag_w;  // NB: clobbers
      siz_w += fre_u->siz_w;

      // XX groace
      //
      pag_w -= HEAP.off_ws * (siz_w - 1);
      som_p  = page_to_post(pag_w);
    }
    else {
      fre_u = NULL;
    }

    ASAN_UNPOISON_MEMORY_REGION(u3a_into(som_p), siz_w << (u3a_page + 2));
    owner.hat_p -= HEAP.dir_ws * (c3_ws)(siz_w << u3a_page);
    HEAP.len_w -= siz_w;

    // fprintf(stderr, "shrink heap 0x%x 0x%x %u:%u (%u) 0x%x\r\n",
    //                 som_p, som_p + (siz_w << u3a_page), pag_w, wiz_w, siz_w, owner.hat_p);

#ifdef SANITY
    assert( HEAP.len_w == post_to_page(owner.hat_p + HEAP.off_ws) );
    assert( dir_u[HEAP.len_w - 1] );
#endif

    if ( fre_u ) {
      _ifree(u3of(u3a_dell, fre_u));
    }

    return wiz_w;
  }

  //  XX madv_free

  ASAN_POISON_MEMORY_REGION(u3a_into(som_p), siz_w << (u3a_page + 2));

  //  XX add temporary freelist entry?
  // if (  !HEAP.cac_p && !HEAP.fre_p
  //    && !HEAP.wee_p[(c3_bits_word(c3_wiseof(*cac_u) - 1) - u3a_min_log)] )
  // {
  //   fprintf(stderr, "palloc: growing heap to free pages\r\n");
  // }

  if ( !HEAP.cac_p ) {
    fre_p = owner_dell_take();
  }
  else {
    fre_p = HEAP.cac_p;
    HEAP.cac_p = 0;
  }

  cac_u = u3to(u3a_dell, fre_p);
  cac_u->pag_w = pag_w;
  cac_u->siz_w = siz_w;

  if ( !(fre_u = u3tn(u3a_dell, HEAP.fre_p)) ) {
    // fprintf(stderr, "free pages 0x%x (%u) via 0x%x\r\n", som_p, siz_w, HEAP.cac_p);
    cac_u->nex_p = 0;
    cac_u->pre_p = 0;
    HEAP.fre_p = HEAP.erf_p = fre_p;
    fre_p = 0;
  }
  else {
    c3_w fex_w;

    while (  ((fex_w = fre_u->pag_w + fre_u->siz_w) < pag_w)
          && fre_u->nex_p )
    {
      fre_u = u3to(u3a_dell, fre_u->nex_p);
    }

    if ( fre_u->pag_w > nex_w ) {        //  insert before
      cac_u->nex_p = u3of(u3a_dell, fre_u);
      cac_u->pre_p = fre_u->pre_p;

      fre_u->pre_p = fre_p;

      //  XX sanity
      if ( cac_u->pre_p ) {
        u3to(u3a_dell, cac_u->pre_p)->nex_p = fre_p;
      }
      else {
        HEAP.fre_p = fre_p;
      }

      fre_p = 0;
    }
    else if ( fex_w == pag_w ) {  //  append to entry
      fre_u->siz_w += siz_w;

      //  coalesce with next entry
      //
      if (  fre_u->nex_p
         && ((fex_w + siz_w) == u3to(u3a_dell, fre_u->nex_p)->pag_w) )
      {
        del_u = u3to(u3a_dell, fre_u->nex_p);
        fre_u->siz_w += del_u->siz_w;
        fre_u->nex_p  = del_u->nex_p;

        //  XX sanity
        if ( del_u->nex_p ) {
          u3to(u3a_dell, del_u->nex_p)->pre_p = u3of(u3a_dell, fre_u);
        }
        else {
          HEAP.erf_p = u3of(u3a_dell, fre_u);
        }
      }
    }
    else if ( fre_u->pag_w == nex_w ) {  //  prepend to entry
      fre_u->siz_w += siz_w;
      fre_u->pag_w  = pag_w;
    }
    else if ( !fre_u->nex_p ) {          //  insert after
      cac_u->nex_p = 0;
      cac_u->pre_p = u3of(u3a_dell, fre_u);
      HEAP.erf_p = fre_u->nex_p = fre_p;
      fre_p = 0;
    }
    else {
      fprintf(stderr, "\033[31m"
                      "palloc: free list hosed at som_p=0x%x pag=%u len=%u\r\n"
                      "\033[0m",
                      (u3_post)u3of(u3a_dell, fre_u), fre_u->pag_w, fre_u->siz_w);
      u3_assert(!"loom: corrupt"); return 0;
    }
  }

  if ( fre_p ) {
    if ( !HEAP.cac_p ) {
      HEAP.cac_p = fre_p;
    }
    else {
      _ifree(fre_p);
    }

    if ( del_u ) {
      _ifree(u3of(u3a_dell, del_u));
    }
  }

  return siz_w;
}

static void
_free_words(u3_post som_p, c3_w pag_w, u3_post dir_p)
{
  (void)pag_w;
  u3a_crag *pag_u = u3to(u3a_crag, dir_p);
  u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);

#ifdef SANITY
  assert( page_to_post(pag_u->pag_w) == (som_p & ~((1U << u3a_page) - 1)) );
  assert( pag_u->log_s < u3a_page );
#endif

  c3_g bit_g = pag_u->log_s - u3a_min_log;
  c3_w pos_w = (som_p & ((1U << u3a_page) - 1)) >> pag_u->log_s;
  const u3a_hunk_dose *hun_u = &(u3a_Hunk[bit_g]);

  if ( som_p & (hun_u->len_s - 1) ) {
    fprintf(stderr, "\033[31m"
                    "palloc: bad alignment som_p=0x%x pag=%u cag=0x%x len_s=%u\r\n"
                    "\033[0m",
                    som_p, post_to_page(som_p), dir_p, hun_u->len_s);
    u3_assert(!"loom: corrupt"); return;
  }

  if ( pag_u->map_w[pos_w >> 5] & (1U << (pos_w & 31)) ) {
    fprintf(stderr, "\033[31m"
                    "palloc: double free som_p=0x%x pag=0x%x\r\n"
                    "\033[0m",
                    som_p, dir_p);
    u3_assert(!"loom: corrupt"); return;
  }

  pag_u->map_w[pos_w >> 5] |= (1U << (pos_w & 31));
  pag_u->fre_s++;

  ASAN_POISON_MEMORY_REGION(u3a_into(som_p), hun_u->len_s << 2);

  {
    u3_post *bit_p = &(HEAP.wee_p[bit_g]);
    u3a_crag *bit_u, *nex_u;

    if ( 1 == pag_u->fre_s ) {
      //  page newly non-full, link
      //

      if ( 1 ) /* independent arena: stable home-style ordering */ {
        while ( *bit_p ) {
          bit_u = u3to(u3a_crag, *bit_p);
          nex_u = u3tn(u3a_crag, bit_u->nex_p);

          if ( nex_u && (nex_u->pag_w < pag_u->pag_w) ) {
            bit_p = &(bit_u->nex_p);
            continue;
          }

          break;
        }
      }

      pag_u->nex_p = *bit_p;
      *bit_p = dir_p;
    }
    else if ( pag_u->fre_s == hun_u->ful_s ) {
      //  page now free
      //
      while ( *bit_p != dir_p ) {
        bit_u = u3to(u3a_crag, *bit_p);
        bit_p = &(bit_u->nex_p);

        //  XX sanity: must be in list
      }

      *bit_p = pag_u->nex_p;

      dir_u[pag_u->pag_w] = u3a_head_pg;
      som_p = page_to_post(pag_u->pag_w); // NB: clobbers
      if ( som_p != dir_p ) {
        _ifree(dir_p);
      }
      _ifree(som_p);
    }
  }
}

static void
_ifree(u3_post som_p)
{
  if ( owner_dell_release(som_p) ) return;
  u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
  c3_w pag_w = post_to_page(som_p);

  if ( pag_w >= HEAP.len_w ) {
    fprintf(stderr, "\033[31m"
                    "palloc: page out of heap som_p=0x%x pag_w=%u len_w=%u\r\n"
                    "\033[0m",
                    som_p, pag_w, HEAP.len_w);
    u3_assert(!"loom: corrupt"); return;
  }

  u3_post dir_p = dir_u[pag_w];

  if ( dir_p <= u3a_rest_pg ) {
    (void)_free_pages(som_p, pag_w, dir_p);
  }
  else {
    _free_words(som_p, pag_w, dir_p);
  }
}

static u3_post
_irealloc(u3_post som_p, c3_w len_w)
{
  u3p(u3a_crag) *dir_u = u3to(u3p(u3a_crag), HEAP.pag_p);
  c3_w pag_w = post_to_page(som_p);
  c3_w old_w;

    if ( pag_w >= HEAP.len_w ) {
    fprintf(stderr, "\033[31m"
                    "palloc: realloc page out of heap som_p=0x%x pag_w=%u\r\n"
                    "\033[0m",
                    som_p, pag_w);
    u3_assert(!"loom: corrupt"); return 0;
  }

  u3_post dir_p = dir_u[pag_w];

  if ( u3a_head_pg == dir_p ) {
    if ( som_p & ((1U << u3a_page) - 1) ) {
      fprintf(stderr, "\033[31m"
                      "palloc: realloc bad page alignment som_p=0x%x\r\n"
                      "\033[0m",
                      som_p);
      u3_assert(!"loom: corrupt"); return 0;
    }

    {
      c3_w dif_w, siz_w = _pages_size(pag_w);

      old_w = siz_w << u3a_page;

      if (  (len_w < old_w)
         && (dif_w = (old_w - len_w) >> u3a_page) )
      {
        pag_w += HEAP.dir_ws * (siz_w - dif_w);
        (void)_free_pages(page_to_post(pag_w), pag_w, u3a_head_pg);

        // XX junk
        //  XX unpoison prefix, poison suffix
        return som_p;
      }

      //  XX also grow in place if sufficient adjacent pages are free?
    }
  }
  else if ( u3a_rest_pg >= dir_p ) {
    fprintf(stderr, "\033[31m"
                    "palloc: realloc wrong page som_p=0x%x\r\n"
                    "\033[0m",
                    som_p);
    u3_assert(!"loom: corrupt"); return 0;
  }
  else {
    u3a_crag *pag_u = u3to(u3a_crag, dir_p);
    c3_w pos_w = (som_p & ((1U << u3a_page) - 1)) >> pag_u->log_s;
    const u3a_hunk_dose *hun_u = &(u3a_Hunk[pag_u->log_s - u3a_min_log]);

    if ( som_p & (hun_u->len_s - 1) ) {
      fprintf(stderr, "\033[31m"
                      "palloc: realloc bad alignment som_p=0x%x pag=0x%x len_s=%u\r\n"
                      "\033[0m",
                      som_p, dir_p, hun_u->len_s);
      u3_assert(!"loom: corrupt"); return 0;
    }

    if ( pag_u->map_w[pos_w >> 5] & (1U << (pos_w & 31)) ) {
      fprintf(stderr, "\033[31m"
                      "palloc: realloc free som_p=0x%x pag=0x%x\r\n"
                      "\033[0m",
                      som_p, dir_p);
      u3_assert(!"loom: corrupt"); return 0;
    }

    old_w = hun_u->len_s;

    if (  (len_w <= old_w)
       && ((len_w > (old_w >> 1)) || (u3a_minimum == old_w)) )
    {
      //  XX junk
      //  XX unpoison prefix, poison suffix
      return som_p;
    }
  }

  {
    u3_post new_p = _imalloc(len_w);
    if ( !new_p ) return 0;

    memcpy(u3a_into(new_p), u3a_into(som_p), (c3_z)c3_min(len_w, old_w) << 2);
    _ifree(som_p);

    return new_p;
  }
}
