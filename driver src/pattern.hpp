#pragma once
#include "utils.hpp"

namespace memory
{
	std::uintptr_t from_pattern( PLDR_DATA_TABLE_ENTRY _module, const char* sig, const char* mask )
	{
		for ( std::uintptr_t i = 0; i < _module->SizeOfImage; i++ )
			if ( [ ]( std::uint8_t const* data, std::uint8_t const* sig, char const* mask )
				 {
					 for ( ; *mask; ++mask, ++data, ++sig )
					 {
						 if ( *mask == 'x' && *data != *sig ) return false;
					 }
					 return ( *mask ) == 0;
				 }( ( std::uint8_t* )( reinterpret_cast< std::uintptr_t >( _module->DllBase ) + i ), ( std::uint8_t* )sig, mask ) )
				return reinterpret_cast< std::uintptr_t >( _module->DllBase ) + i;

		return 0;
	}
}